# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""
Iterative, DNSSEC-validating resolver for ECDSA P-256, ML-DSA-44 and ML-DSA-44-MTL.

Walks root -> TLD -> SLD from a trust anchor, validates every RRset it uses (including NSEC
denial of existence), caches keys, answers and verified ladders, and falls back from UDP to
TCP on TC=1.

profile   "base"   : no SigTag option (every MTL RRSIG arrives as a full signature)
          "sigtag" : SigTag option with the tags of the ladders cached for that zone
          "abhed"  : SigTag + ABHED option (path trimming + compact condensed signatures)
tcp_first True     : go straight to TCP when the answer is known not to fit in UDP
                     (DNSKEY of a PQ zone; any data of an ML-DSA-44 zone; MTL zone in base profile)
"""
from __future__ import annotations

import socket
import struct
import time

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype as T

from . import mtl
from .dnssec import COUNTERS, ds_digest, signing_data_from_rrsig, verify_raw
from .params import (ABHED_F_COMPACT, ABHED_F_TRIM, ALG_ECDSAP256, ALG_MLDSA44, ALG_MTL,
                     MAX_SIGTAGS, OPT_ABHED, OPT_SIGTAG, UDP_LIMIT)

PQ_ALGS = (ALG_MLDSA44, ALG_MTL)
STAT_KEYS = ("exchanges", "udp", "tcp", "tc", "bytes_tx", "bytes_rx", "round_trips", "retries",
             "ladders_verified", "ladder_cache_hits", "cache_hits")


class Bogus(Exception):
    pass


class NeedLadder(Exception):
    pass


class DirectTransport:
    """In-process transport: calls AuthServer.handle() directly (deterministic, no sockets)."""

    def __init__(self, servers: dict):
        self.servers = servers

    def exchange(self, ip: str, wire: bytes, tcp: bool) -> bytes:
        out = self.servers[ip].handle(wire, tcp)
        if out is None:
            raise Bogus(f"no response from {ip}")
        return out


class NetTransport:
    """Real UDP/TCP sockets. addr_map lets a lab IP be redirected to (host, port)."""

    def __init__(self, addr_map: dict | None = None, timeout: float = 3.0, port: int = 53):
        self.addr_map, self.timeout, self.port = addr_map or {}, timeout, port

    def exchange(self, ip: str, wire: bytes, tcp: bool) -> bytes:
        addr = self.addr_map.get(ip, (ip, self.port))
        if not tcp:
            for _ in range(3):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(wire, addr)
                    try:
                        data, _ = s.recvfrom(65535)
                        if data[:2] == wire[:2]:
                            return data
                    except socket.timeout:
                        continue
            raise Bogus(f"UDP timeout from {addr}")
        with socket.create_connection(addr, timeout=self.timeout) as s:
            s.sendall(struct.pack(">H", len(wire)) + wire)
            hdr = _recvn(s, 2)
            return _recvn(s, struct.unpack(">H", hdr)[0])


def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise Bogus("TCP connection closed")
        buf += chunk
    return buf


class _Zone:
    def __init__(self, name, ip, ds):
        self.name, self.ip, self.ds = name, ip, ds      # ds: [(tag, alg, digest)]
        self.keys: dict = {}                            # (tag, alg) -> [public key bytes]
        self.data_alg = None
        self.dnskey_msg = None


class Resolver:
    def __init__(self, transport, root_ip: str, trust_anchor: str, profile: str = "base",
                 tcp_first: bool = False, ladder_cache: bool = True, answer_cache: bool = True,
                 payload: int = UDP_LIMIT, now=None):
        assert profile in ("base", "sigtag", "abhed")
        self.t, self.profile, self.tcp_first = transport, profile, tcp_first
        self.ladder_cache, self.answer_cache, self.payload = ladder_cache, answer_cache, payload
        self.now = now
        tag, alg, _, digest = trust_anchor.split()
        root = _Zone(dns.name.root, root_ip, [(int(tag), int(alg), bytes.fromhex(digest))])
        self.zones = {dns.name.root: root}
        self.ladders: dict = {}          # zone name -> {SigTag: Ladder}   (verified)
        self.cache: dict = {}
        self.s = dict.fromkeys(STAT_KEYS, 0)
        self._msg_ladder = None

    # ------------------------------------------------------------------ statistics
    def snapshot(self) -> dict:
        d = dict(self.s)
        d.update(mldsa_verifies=COUNTERS["mldsa_verify"], ecdsa_verifies=COUNTERS["ecdsa_verify"],
                 hashes=mtl.COUNTERS["hashes"], crypto_s=COUNTERS["crypto_s"])
        return d

    def cache_bytes(self) -> dict:
        lad = sum(len(l.to_bytes()) for z in self.ladders.values() for l in z.values())
        keys = sum(len(p) for z in self.zones.values() for ps in z.keys.values() for p in ps)
        return {"ladders": sum(len(z) for z in self.ladders.values()), "ladder_bytes": lad,
                "key_bytes": keys}

    # ------------------------------------------------------------------ transport
    def _tags(self, zone: _Zone) -> list:
        ls = sorted(self.ladders.get(zone.name, {}).values(), key=lambda l: -l.n)
        return [l.tag for l in ls[:MAX_SIGTAGS]]

    def _skip_udp(self, zone: _Zone, qtype) -> bool:
        if not self.tcp_first:
            return False
        if qtype == T.DNSKEY:
            return any(alg in PQ_ALGS for _, alg, _ in zone.ds)
        if zone.data_alg == ALG_MLDSA44:
            return True
        return zone.data_alg == ALG_MTL and self.profile == "base"

    def _ask(self, zone: _Zone, qname, qtype, with_opt=True):
        opts, tags = [], []
        if self.profile != "base" and with_opt:
            tags = self._tags(zone)
            opts.append(dns.edns.GenericOption(OPT_SIGTAG, b"".join(tags)))
            if self.profile == "abhed":
                opts.append(dns.edns.GenericOption(OPT_ABHED, bytes([ABHED_F_TRIM | ABHED_F_COMPACT])))
        q = dns.message.make_query(qname, qtype, want_dnssec=True, payload=self.payload, options=opts)
        q.flags &= ~dns.flags.RD
        wire = q.to_wire()
        tcp = self._skip_udp(zone, qtype)
        self.s["exchanges"] += 1
        if not tcp:
            data = self.t.exchange(zone.ip, wire, False)
            self.s["udp"] += 1; self.s["round_trips"] += 1
            self.s["bytes_tx"] += len(wire); self.s["bytes_rx"] += len(data)
            msg = dns.message.from_wire(data)
            if msg.flags & dns.flags.TC:
                self.s["tc"] += 1
                tcp = True
        if tcp:
            data = self.t.exchange(zone.ip, wire, True)
            self.s["tcp"] += 1; self.s["round_trips"] += 2
            self.s["bytes_tx"] += len(wire) + 2; self.s["bytes_rx"] += len(data) + 2
            msg = dns.message.from_wire(data)
        return msg, tags, len(data)

    # ------------------------------------------------------------------ signature validation
    def _ingest(self, zone: _Zone, pubs: list, sl: mtl.SignedLadder) -> mtl.Ladder:
        lad = sl.ladder
        store = self.ladders.setdefault(zone.name, {})
        known = store.get(lad.tag)
        if self.ladder_cache and known is not None and known.to_bytes() == lad.to_bytes():
            self.s["ladder_cache_hits"] += 1
            return known
        if not lad.well_formed():
            raise Bogus("malformed ladder")
        if not any(verify_raw(ALG_MTL, p, lad.to_bytes(), sl.signature) for p in pubs):
            raise Bogus(f"bad ML-DSA-44 signature on ladder of {zone.name}")
        self.s["ladders_verified"] += 1
        if self.ladder_cache:
            store[lad.tag] = lad
            for tag in sorted(store, key=lambda t: -store[t].n)[MAX_SIGTAGS:]:
                del store[tag]
        return lad

    def _check(self, zone: _Zone, rrset, rrsig, tags) -> None:
        now = self.now or time.time()
        if not (rrsig.inception <= now <= rrsig.expiration):
            raise Bogus(f"signature on {rrset.name} outside validity period")
        if rrsig.signer != zone.name:
            raise Bogus("unexpected signer")
        alg = int(rrsig.algorithm)
        pubs = zone.keys.get((rrsig.key_tag, alg))
        if not pubs:
            raise Bogus(f"no DNSKEY {rrsig.key_tag}/{alg} for {zone.name}")
        data, sig = signing_data_from_rrsig(rrset, rrsig), rrsig.signature
        if alg in (ALG_ECDSAP256, ALG_MLDSA44):
            ok = any(verify_raw(alg, p, data, sig) for p in pubs)
        elif alg == ALG_MTL:
            ok = self._check_mtl(zone, pubs, data, sig, tags)
        else:
            raise Bogus(f"unsupported algorithm {alg}")
        if not ok:
            raise Bogus(f"bad signature on {rrset.name} {T.to_text(rrset.rdtype)}")

    def _check_mtl(self, zone, pubs, data, sig, tags) -> bool:
        t0 = time.perf_counter()
        try:
            kind = sig[0]
            if kind == mtl.T_FULL:
                c, off = mtl.Condensed.from_bytes(sig, 1)
                sl, end = mtl.SignedLadder.from_bytes(sig, off)
                if end != len(sig) or c.flags or sl.ladder.sid != c.sid:
                    return False
                # cheap hash check first, expensive ML-DSA check second (draft Appendix C)
                if not mtl.verify_path(data, c.sid, c.rand, c.leaf, c.sibs, sl.ladder):
                    return False
                COUNTERS["crypto_s"] += time.perf_counter() - t0
                t0 = None
                self._msg_ladder = self._ingest(zone, pubs, sl)
                return True
            if kind == mtl.T_COND:
                c, end = mtl.Condensed.from_bytes(sig, 1)
                if end != len(sig) or c.flags:
                    return False
                cands = [l for l in self.ladders.get(zone.name, {}).values() if l.sid == c.sid]
                if self._msg_ladder is not None and self._msg_ladder.sid == c.sid:
                    cands.append(self._msg_ladder)
                if not cands:
                    raise NeedLadder()
                return any(mtl.verify_path(data, c.sid, c.rand, c.leaf, c.sibs, l) for l in cands)
            if kind == mtl.T_COMPACT and self.profile == "abhed":
                ref, rand, leaf, sibs = mtl.decode_compact(sig)
                if ref == mtl.REF_IN_RESPONSE:
                    lad = self._msg_ladder
                else:
                    lad = self.ladders.get(zone.name, {}).get(tags[ref]) if ref < len(tags) else None
                if lad is None:
                    raise NeedLadder()
                return mtl.verify_path(data, lad.sid, rand, leaf, sibs, lad)
            return False
        except (ValueError, struct.error, IndexError):
            return False
        finally:
            if t0 is not None:
                COUNTERS["crypto_s"] += time.perf_counter() - t0

    def _validate_msg(self, zone: _Zone, msg, tags) -> None:
        """Validate every signed RRset in answer + authority (delegation NS sets are unsigned)."""
        self._msg_ladder = None
        todo = []
        for section in (msg.answer, msg.authority):
            sigs = {(r.name, r.covers): r for r in section if r.rdtype == T.RRSIG}
            for r in section:
                if r.rdtype == T.RRSIG:
                    continue
                if r.rdtype == T.NS and r.name != zone.name:
                    continue
                s = sigs.get((r.name, r.rdtype))
                if s is None:
                    raise Bogus(f"unsigned RRset {r.name} {T.to_text(r.rdtype)}")
                todo.append((r, s[0]))
        # full signatures first: they carry the ladder the condensed ones in this message need
        todo.sort(key=lambda p: 0 if (int(p[1].algorithm) == ALG_MTL and p[1].signature[:1] == b"\x01") else 1)
        for rrset, rrsig in todo:
            self._check(zone, rrset, rrsig, tags)

    def _fetch(self, zone: _Zone, qname, qtype):
        """Query + validate; on a condensed signature we cannot verify, retry asking for full ones."""
        msg, tags, size = self._ask(zone, qname, qtype)
        try:
            self._validate_msg(zone, msg, tags)
        except (NeedLadder, Bogus):
            if self.profile == "base":
                raise Bogus(f"validation failed for {qname}")
            self.s["retries"] += 1
            msg, tags, size = self._ask(zone, qname, qtype, with_opt=False)
            try:
                self._validate_msg(zone, msg, tags)
            except NeedLadder:
                raise Bogus("condensed signature without a ladder")
        return msg, size

    # ------------------------------------------------------------------ chain of trust
    def _ensure_keys(self, zone: _Zone):
        if zone.keys:
            return
        msg, _, _ = self._ask(zone, zone.name, T.DNSKEY)
        rr = next((r for r in msg.answer if r.rdtype == T.DNSKEY and r.name == zone.name), None)
        if rr is None:
            raise Bogus(f"no DNSKEY for {zone.name}")
        anchors = [k for k in rr for (tag, alg, dg) in zone.ds
                   if int(k.algorithm) == alg and ds_digest(zone.name, k) == dg]
        if not anchors:
            raise Bogus(f"DNSKEY of {zone.name} does not match DS / trust anchor")
        import dns.dnssec
        for k in rr:
            zone.keys.setdefault((dns.dnssec.key_id(k), int(k.algorithm)), []).append(bytes(k.key))
        trusted = {(dns.dnssec.key_id(k), int(k.algorithm)) for k in anchors}
        all_keys, zone.keys = zone.keys, {k: v for k, v in zone.keys.items() if k in trusted}
        try:
            self._validate_msg(zone, msg, [])
        except Exception:
            zone.keys = {}
            raise
        zone.keys = all_keys
        zsk = [int(k.algorithm) for k in rr if k.flags == 256]
        zone.data_alg = zsk[0] if zsk else int(anchors[0].algorithm)

    def _zone_for(self, qname) -> _Zone:
        best = self.zones[dns.name.root]
        for name, z in self.zones.items():
            if qname.is_subdomain(name) and len(name.labels) > len(best.name.labels):
                best = z
        return best

    def resolve(self, qname, qtype=T.A) -> dict:
        qname = dns.name.from_text(qname).canonicalize() if isinstance(qname, str) else qname
        qtype = T.from_text(qtype) if isinstance(qtype, str) else qtype
        key = (qname, qtype)
        hit = self.cache.get(key)
        if hit and hit["expires"] > time.monotonic():
            self.s["cache_hits"] += 1
            return dict(hit, from_cache=True)
        zone = self._zone_for(qname)
        for _ in range(12):
            self._ensure_keys(zone)
            msg, size = self._fetch(zone, qname, qtype)
            ns = next((r for r in msg.authority if r.rdtype == T.NS and r.name != zone.name
                       and qname.is_subdomain(r.name)), None)
            if ns is not None and not (msg.flags & dns.flags.AA):
                ds = next((r for r in msg.authority if r.rdtype == T.DS and r.name == ns.name), None)
                if ds is None:
                    raise Bogus(f"insecure delegation {ns.name} (not supported in the lab)")
                glue = next((r for r in msg.additional if r.rdtype == T.A
                             and r.name in {x.target for x in ns}), None)
                if glue is None:
                    raise Bogus("referral without glue")
                zone = _Zone(ns.name, glue[0].address,
                             [(d.key_tag, int(d.algorithm), bytes(d.digest)) for d in ds])
                self.zones[ns.name] = zone
                continue
            rcode = msg.rcode()
            answer = [r for r in msg.answer if r.rdtype != T.RRSIG]
            if rcode == dns.rcode.NOERROR and answer:
                if not any(r.name == qname and r.rdtype == qtype for r in answer):
                    raise Bogus("answer does not match the question")
                ttl = min(r.ttl for r in answer)
            else:
                self._check_denial(zone, msg, qname, qtype, rcode)
                ttl = 300
            res = {"rcode": dns.rcode.to_text(rcode), "answer": answer, "status": "SECURE",
                   "zone": zone.name.to_text(), "answer_bytes": size, "from_cache": False,
                   "message": msg, "expires": time.monotonic() + ttl}
            if self.answer_cache:
                self.cache[key] = res
            return res
        raise Bogus("too many referrals")

    @staticmethod
    def _check_denial(zone, msg, qname, qtype, rcode):
        nsecs = [r for r in msg.authority if r.rdtype == T.NSEC]
        if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) or not nsecs:
            raise Bogus(f"unproven negative answer ({dns.rcode.to_text(rcode)})")

        def covers(r, name):
            nxt = r[0].next
            return r.name < name and (name < nxt or nxt == zone.name)

        def has_type(r, t):
            for window, bitmap in r[0].windows:
                if window == t // 256 and len(bitmap) > (t % 256) // 8:
                    return bool(bitmap[(t % 256) // 8] & (0x80 >> (t % 8)))
            return False

        if rcode == dns.rcode.NXDOMAIN:
            if not any(covers(r, qname) for r in nsecs):
                raise Bogus("NXDOMAIN without a covering NSEC")
        else:
            exact = next((r for r in nsecs if r.name == qname), None)
            if exact is not None:
                if has_type(exact, qtype) or has_type(exact, T.CNAME):
                    raise Bogus("NODATA contradicted by the NSEC type bitmap")
            elif not any(covers(r, qname) for r in nsecs):
                raise Bogus("NODATA without a matching NSEC")

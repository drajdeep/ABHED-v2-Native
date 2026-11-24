# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""
Authoritative server for one pre-signed zone bundle (UDP + TCP, EDNS, DO, TC, NSEC denial,
referrals). It never holds a private key.

For ML-DSA-44-MTL RRSIGs the signature field is composed per response:
  * no SigTag option in the query            -> MTL-Type 0x01 full signature (base draft)
  * SigTag option, a tag matches             -> MTL-Type 0x02 condensed signature
  * SigTag option, no tag matches            -> full signature once per response, the other
                                                RRSIGs under the same ladder are condensed
  * SigTag + ABHED option                    -> additionally path trimming / compact 0xF1
A UDP response larger than the limit is replaced by a TC=1 response (TCP is the fallback).
"""
from __future__ import annotations

import bisect
import json
import socket
import socketserver
import sqlite3
import struct
import threading
import time

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype as T
import dns.rrset

from . import mtl
from .dnssec import make_rrsig
from .params import (ABHED_F_COMPACT, ABHED_F_TRIM, ALG_MTL, MAX_SIGTAGS, OPT_ABHED, OPT_SIGTAG,
                     UDP_LIMIT)

TAG_LEN = mtl.SID_LEN + 8


class _Ctx:
    def __init__(self):
        self.do = False
        self.has_opt = False
        self.tags: list = []        # [(sid, right_index)]
        self.flags = 0
        self.sent_full = False


class AuthServer:
    def __init__(self, bundle: str, udp_limit: int = UDP_LIMIT):
        self.bundle, self.udp_limit = str(bundle), udp_limit
        self.lock = threading.Lock()
        self.stats = {"queries": 0, "tc": 0, "full": 0, "condensed": 0, "compact": 0, "formerr": 0}
        self.reload()

    def reload(self):
        with self.lock:
            db = sqlite3.connect(self.bundle, check_same_thread=False)
            meta = json.loads(db.execute("SELECT v FROM meta WHERE k='json'").fetchone()[0])
            self.signed_ladder = bytes(db.execute(
                "SELECT v FROM meta WHERE k='signed_ladder'").fetchone()[0])
            self.db, self.meta = db, meta
            self.origin = dns.name.from_text(meta["origin"])
            self.names = sorted(dns.name.from_text(n) for n in meta["names"])
            self.nameset = set(self.names)
            self.cuts = [dns.name.from_text(c) for c in meta["cuts"]]
            self.sid = bytes.fromhex(meta["sid"]) if "sid" in meta else None
            self.n = meta.get("n", 0)
            self._rr_cache, self._sig_cache = {}, {}

    # ------------------------------------------------------------------ data access
    def _rr(self, name, t):
        key = (name, t)
        if key not in self._rr_cache:
            with self.lock:
                row = self.db.execute("SELECT ttl, rdata FROM rr WHERE name=? AND type=?",
                                      (name.to_text(), t)).fetchone()
            rrs = None
            if row:
                rrs = dns.rrset.RRset(name, dns.rdataclass.IN, t)
                blob, off = row[1], 0
                while off < len(blob):
                    ln, = struct.unpack_from(">H", blob, off); off += 2
                    rrs.add(dns.rdata.from_wire(dns.rdataclass.IN, t, blob, off, ln), row[0])
                    off += ln
            if len(self._rr_cache) > 50000:
                self._rr_cache.clear()
            self._rr_cache[key] = rrs
        return self._rr_cache[key]

    def _sig(self, name, t):
        with self.lock:
            row = self.db.execute("SELECT hdr, body FROM sig WHERE name=? AND type=?",
                                  (name.to_text(), t)).fetchone()
        return (bytes(row[0]), bytes(row[1])) if row else None

    def _mtl_field(self, body: bytes, ctx: _Ctx) -> bytes:
        if not ctx.has_opt:
            self.stats["full"] += 1
            return bytes([mtl.T_FULL]) + body + self.signed_ladder
        cond, _ = mtl.Condensed.from_bytes(body)
        best = None
        for i, (sid, right) in enumerate(ctx.tags):
            if sid != self.sid or not (cond.leaf <= right < self.n):
                continue
            c = mtl.trim(cond, right + 1) if ctx.flags & ABHED_F_TRIM else cond
            score = (-len(c.sibs), right)
            if best is None or score > best[0]:
                best = (score, i, c)
        if best:
            _, i, c = best
            if ctx.flags & ABHED_F_COMPACT:
                self.stats["compact"] += 1
                return mtl.encode_compact(i, c)
            self.stats["condensed"] += 1
            return bytes([mtl.T_COND]) + c.to_bytes()
        if ctx.sent_full:                               # deduplication within one response
            if ctx.flags & ABHED_F_COMPACT:
                self.stats["compact"] += 1
                return mtl.encode_compact(mtl.REF_IN_RESPONSE, cond)
            self.stats["condensed"] += 1
            return bytes([mtl.T_COND]) + body
        ctx.sent_full = True
        self.stats["full"] += 1
        return bytes([mtl.T_FULL]) + body + self.signed_ladder

    def _add(self, section: list, name, t, ctx: _Ctx, signed=True) -> bool:
        rrs = self._rr(name, t)
        if rrs is None:
            return False
        section.append(rrs)
        if signed and ctx.do:
            s = self._sig(name, t)
            if s:
                hdr, body = s
                field = self._mtl_field(body, ctx) if hdr[2] == ALG_MTL else body
                sig = dns.rrset.RRset(name, dns.rdataclass.IN, T.RRSIG, t)
                sig.add(make_rrsig(hdr, field), rrs.ttl)
                section.append(sig)
        return True

    def _covering(self, name):
        return self.names[max(bisect.bisect_right(self.names, name) - 1, 0)]

    def _exists(self, name) -> bool:                    # real name or empty non-terminal
        if name in self.nameset:
            return True
        i = bisect.bisect_left(self.names, name)
        return i < len(self.names) and self.names[i].is_subdomain(name)

    # ------------------------------------------------------------------ query handling
    def handle(self, wire: bytes, tcp: bool):
        try:
            q = dns.message.from_wire(wire)
            qn, qt = q.question[0].name.canonicalize(), q.question[0].rdtype
        except Exception:
            return None
        self.stats["queries"] += 1
        ctx = _Ctx()
        ctx.do = q.edns >= 0 and bool(q.ednsflags & dns.flags.DO)
        rcode, bad = dns.rcode.NOERROR, False
        for o in (q.options if q.edns >= 0 else ()):
            if o.otype == OPT_SIGTAG:
                data = o.to_wire()
                ctx.has_opt = True
                if len(data) % TAG_LEN or len(data) // TAG_LEN > MAX_SIGTAGS:
                    bad = True
                ctx.tags = [(data[i:i + 32], struct.unpack_from(">Q", data, i + 32)[0])
                            for i in range(0, len(data) - len(data) % TAG_LEN, TAG_LEN)]
            elif o.otype == OPT_ABHED:
                data = o.to_wire()
                ctx.flags = data[0] if data else 0
        r = dns.message.make_response(q, our_payload=self.udp_limit)
        opts = [dns.edns.GenericOption(OPT_SIGTAG, b"")] if ctx.has_opt else []
        if q.edns >= 0:
            r.use_edns(0, dns.flags.DO if ctx.do else 0, self.udp_limit, options=opts)
        if bad:
            self.stats["formerr"] += 1
            r.set_rcode(dns.rcode.FORMERR)
            return r.to_wire()
        if not qn.is_subdomain(self.origin):
            r.set_rcode(dns.rcode.REFUSED)
            return r.to_wire()
        cut = next((c for c in self.cuts if qn.is_subdomain(c)), None)
        if cut is not None and not (qn == cut and qt == T.DS):
            self._add(r.authority, cut, T.NS, ctx, signed=False)
            if not self._add(r.authority, cut, T.DS, ctx):
                self._add(r.authority, cut, T.NSEC, ctx)
            for ns in self._rr(cut, T.NS):
                self._add(r.additional, ns.target, T.A, ctx, signed=False)
        else:
            r.flags |= dns.flags.AA
            if self._add(r.answer, qn, qt, ctx):
                pass
            elif self._exists(qn):                      # NODATA
                self._add(r.authority, self.origin, T.SOA, ctx)
                self._add(r.authority, self._covering(qn), T.NSEC, ctx)
            else:                                       # NXDOMAIN
                rcode = dns.rcode.NXDOMAIN
                ce = qn.parent()
                while not self._exists(ce):
                    ce = ce.parent()
                self._add(r.authority, self.origin, T.SOA, ctx)
                owners = {self._covering(qn), self._covering(dns.name.Name((b"*",) + ce.labels))}
                for o in sorted(owners):
                    self._add(r.authority, o, T.NSEC, ctx)
        r.set_rcode(rcode)
        out = r.to_wire(max_size=65535)
        if not tcp:
            limit = min(q.payload if q.edns >= 0 else 512, self.udp_limit)
            if len(out) > limit:
                self.stats["tc"] += 1
                t = dns.message.make_response(q, our_payload=self.udp_limit)
                if q.edns >= 0:
                    t.use_edns(0, dns.flags.DO if ctx.do else 0, self.udp_limit, options=opts)
                t.flags |= dns.flags.TC
                return t.to_wire()
        return out


# ---------------------------------------------------------------------- network front end
def serve(server: AuthServer, host: str, port: int, rtt_ms: float = 0.0):
    """Start UDP+TCP listeners in daemon threads. rtt_ms emulates one network round trip
    per UDP exchange and two per TCP exchange (handshake + query). Returns (udp, tcp)."""
    delay = rtt_ms / 1000.0

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            out = server.handle(data, False)
            if out is None:
                return
            if delay:
                time.sleep(delay)
            sock.sendto(out, self.client_address)

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            s = self.request
            s.settimeout(10)
            if delay:
                time.sleep(delay)
            try:
                while True:
                    hdr = _recvn(s, 2)
                    if not hdr:
                        return
                    out = server.handle(_recvn(s, struct.unpack(">H", hdr)[0]), True)
                    if out is None:
                        return
                    if delay:
                        time.sleep(delay)
                    s.sendall(struct.pack(">H", len(out)) + out)
            except (OSError, struct.error):
                return

    socketserver.ThreadingUDPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    socketserver.ThreadingUDPServer.daemon_threads = True
    for attempt in range(20):           # port 0: find a port that is free for UDP and TCP
        u = socketserver.ThreadingUDPServer((host, port), UDP)
        try:
            t = socketserver.ThreadingTCPServer((host, u.server_address[1]), TCP)
            break
        except OSError:
            u.server_close()
            if port or attempt == 19:
                raise
    for srv in (u, t):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return u, t


def _recvn(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf

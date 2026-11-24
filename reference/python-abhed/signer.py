# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""
Offline zone signer. Writes one SQLite "bundle" per zone that abhed.authd serves.

Modes (key layout):
  ecdsa    KSK 13 + ZSK 13            classical baseline
  mldsa44  KSK 18 + ZSK 18            draft-westerbaan-dnssec-mldsa
  split    KSK 18 + ZSK 13            PQ KSK / classical ZSK (cf. draft-johani-dnsop-dnssec-alg-split)
  mtl      layout=csk  : one ML-DSA-44-MTL key signs everything (DNSKEY included)
           layout=split: KSK 18 + ZSK ML-DSA-44-MTL

MTL signing is batch signing: every RRset is one leaf, ONE ML-DSA-44 signature covers the ladder.
The signer is stateful (node set + leaf map in the key directory). State is written atomically,
a SID is never reused, and the signer refuses to continue a series with a different key.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import time
from pathlib import Path

import dns.rdataclass
import dns.rdatatype as T
import dns.rrset

from . import mtl
from .dnssec import (COUNTERS, Key, canonical_rrset_wire, ds_text, label_count,
                     rrsig_header_wire, signing_data)
from .params import (ALG_ECDSAP256, ALG_MLDSA44, ALG_MTL, DATASETS, SIG_VALIDITY)
from .zone import Zone, add_nsec_chain, build_iem, build_lab, build_root

MODES = ("ecdsa", "mldsa44", "split", "mtl")
REFRESH_BEFORE = 3 * 86400          # re-leaf an RRset when its RRSIG has less than this left


def _atomic_write(path: Path, data: str):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data)
    os.replace(tmp, path)


class KeyStore:
    def __init__(self, root: Path, zone: str):
        self.dir = Path(root) / (zone.strip(".") or "root")
        self.dir.mkdir(parents=True, exist_ok=True)

    def key(self, role: str, alg: int, flags: int, fresh: bool) -> Key:
        p = self.dir / f"{role}.json"
        if p.exists() and not fresh:
            k = Key.from_json(json.loads(p.read_text()))
            if k.alg == alg and k.flags == flags:
                return k
        k = Key.generate(alg, flags)
        _atomic_write(p, json.dumps(k.to_json()))
        os.chmod(p, 0o600)
        return k

    def load_state(self):
        p = self.dir / "mtl-state.json"
        return json.loads(p.read_text()) if p.exists() else None

    def save_state(self, st):
        _atomic_write(self.dir / "mtl-state.json", json.dumps(st))


def layout_keys(mode: str, layout: str, ks: KeyStore, fresh: bool):
    """-> (keys in DNSKEY RRset, key that signs DNSKEY, key that signs zone data)"""
    if mode == "mtl" and layout == "csk":
        csk = ks.key("csk", ALG_MTL, 257, fresh)
        return [csk], csk, csk
    ksk_alg = ALG_ECDSAP256 if mode == "ecdsa" else ALG_MLDSA44
    zsk_alg = {"ecdsa": ALG_ECDSAP256, "split": ALG_ECDSAP256, "mldsa44": ALG_MLDSA44,
               "mtl": ALG_MTL}[mode]
    ksk = ks.key("ksk", ksk_alg, 257, fresh)
    zsk = ks.key("zsk", zsk_alg, 256, fresh)
    return [ksk, zsk], ksk, zsk


def _digest(rrs) -> str:
    return hashlib.sha256(canonical_rrset_wire(rrs, rrs.ttl)).hexdigest()


def _hot_rank(z: Zone, key) -> int:
    """Leaf placement: larger rank = appended later = smaller rung = shorter proof."""
    name, t = key
    if name != z.origin:
        return 0
    return {T.NSEC: 1, T.NS: 2, T.DNSKEY: 3, T.SOA: 4}.get(t, 0)


def sign_zone(z: Zone, mode: str, ks: KeyStore, out: Path, *, layout="csk", leaf_order="hot-last",
              fresh=True, now=None, child_ds=None) -> dict:
    """Sign z and write the bundle to out. Returns metadata (incl. the DS text for the parent)."""
    assert mode in MODES
    now = int(now or time.time())
    t_start = time.perf_counter()
    c0 = dict(COUNTERS); h0 = mtl.COUNTERS["hashes"]
    keys, dnskey_signer, data_signer = layout_keys(mode, layout, ks, fresh)
    for name, ds in (child_ds or {}).items():
        z.rrsets.pop((name, T.DS), None)
        z.add(name, T.DS, ds)
    z.rrsets.pop((z.origin, T.DNSKEY), None)
    for k in keys:
        z.add(z.origin, T.DNSKEY, k.dnskey())
    add_nsec_chain(z)
    inception, expiration = now - 3600, now + SIG_VALIDITY

    def signer_of(key):
        return dnskey_signer if key[1] == T.DNSKEY else data_signer

    def hdr(rrs, k: Key, inc, exp):
        return rrsig_header_wire(rrs.rdtype, k.alg, label_count(rrs.name), rrs.ttl, exp, inc,
                                 k.tag(), z.origin)

    signable = sorted(k for k in z.rrsets if z.signable(*k))
    sigs: dict = {}                 # key -> (hdr, body)
    meta = {"origin": z.origin.to_text(), "mode": mode, "layout": layout,
            "leaf_order": leaf_order, "signed_at": now}

    mtl_keys = [k for k in signable if signer_of(k).alg == ALG_MTL]
    for key in signable:
        if signer_of(key).alg != ALG_MTL:
            rrs, k = z.rrsets[key], signer_of(key)
            h = hdr(rrs, k, inception, expiration)
            sigs[key] = (h, k.sign(signing_data(rrs, h, rrs.ttl)))

    if mtl_keys:
        mk = data_signer
        st = None if fresh else ks.load_state()
        if st and st["pub"] != mk.pub.hex():
            raise SystemExit("MTL state belongs to another key: refusing to reuse the series "
                             "(run a fresh sign instead of evolve)")
        ns = mtl.NodeSet.from_json(st["nodeset"]) if st else mtl.NodeSet()
        leafmap = st["leafmap"] if st else {}
        todo = []
        for key in mtl_keys:
            rrs = z.rrsets[key]
            e = leafmap.get(f"{key[0].to_text()}|{key[1]}")
            if e and e["digest"] == _digest(rrs) and e["exp"] - now > REFRESH_BEFORE:
                continue
            todo.append(key)
        if leaf_order == "hot-last":
            todo.sort(key=lambda k: (_hot_rank(z, k), k))
        new_map, todo_set = {}, set(todo)
        for key in mtl_keys:
            ident = f"{key[0].to_text()}|{key[1]}"
            if key not in todo_set:
                new_map[ident] = leafmap[ident]
        for key in todo:
            rrs = z.rrsets[key]
            h = hdr(rrs, mk, inception, expiration)
            leaf = ns.append(signing_data(rrs, h, rrs.ttl))
            new_map[f"{key[0].to_text()}|{key[1]}"] = {"leaf": leaf, "digest": _digest(rrs),
                                                        "inc": inception, "exp": expiration}
        ladder = ns.ladder()
        signed = mtl.SignedLadder(ladder, mk.sign(ladder.to_bytes()))
        for key in mtl_keys:
            e = new_map[f"{key[0].to_text()}|{key[1]}"]
            sigs[key] = (hdr(z.rrsets[key], mk, e["inc"], e["exp"]),
                         ns.authpath(e["leaf"]).to_bytes())
        ks.save_state({"pub": mk.pub.hex(), "nodeset": ns.to_json(), "leafmap": new_map})
        meta.update(sid=ns.sid.hex(), n=ns.count, rungs=len(ladder.rungs),
                    signed_ladder_bytes=len(signed.to_bytes()), new_leaves=len(todo))
    else:
        signed = None

    sign_s = time.perf_counter() - t_start
    meta.update(alg_data=data_signer.alg, alg_dnskey=dnskey_signer.alg, rrsets=len(signable),
                sign_s=sign_s, hashes=mtl.COUNTERS["hashes"] - h0,
                mldsa_signs=COUNTERS["mldsa_sign"] - c0["mldsa_sign"],
                ecdsa_signs=COUNTERS["ecdsa_sign"] - c0["ecdsa_sign"],
                cuts=[c.to_text() for c in sorted(z.cuts)],
                ds=ds_text(z.origin, dnskey_signer.dnskey()))
    _write_bundle(z, sigs, signed, meta, Path(out))
    return meta


def _write_bundle(z: Zone, sigs, signed, meta, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    db.executescript("""
        CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB);
        CREATE TABLE rr(name TEXT, type INT, ttl INT, rdata BLOB, PRIMARY KEY(name, type));
        CREATE TABLE sig(name TEXT, type INT, hdr BLOB, body BLOB, PRIMARY KEY(name, type));
    """)
    rows = []
    for (name, t), rrs in z.rrsets.items():
        blob = b"".join(struct.pack(">H", len(w)) + w for w in (rd.to_wire() for rd in rrs))
        rows.append((name.to_text(), t, rrs.ttl, blob))
    db.executemany("INSERT INTO rr VALUES(?,?,?,?)", rows)
    db.executemany("INSERT INTO sig VALUES(?,?,?,?)",
                   [(n.to_text(), t, h, b) for (n, t), (h, b) in sigs.items()])
    meta = dict(meta, names=[n.to_text() for n in z.auth_names()])
    db.execute("INSERT INTO meta VALUES('json', ?)", (json.dumps(meta),))
    db.execute("INSERT INTO meta VALUES('signed_ladder', ?)", (signed.to_bytes() if signed else b"",))
    db.commit(); db.close()
    os.replace(tmp, out)


def sign_all(mode: str, hosts: int, out: Path, keys: Path, *, layout="csk", leaf_order="hot-last",
             fresh=True, serial=None, now=None) -> dict:
    """Sign iem.lab., lab. and the root (children first, so parents can publish the DS)."""
    out, keys = Path(out), Path(keys)
    serial = serial or int(time.time())
    opts = dict(layout=layout, leaf_order=leaf_order, fresh=fresh, now=now)
    m_iem = sign_zone(build_iem(serial, hosts), mode, KeyStore(keys, "iem.lab."), out / "iem.lab.db", **opts)
    m_lab = sign_zone(build_lab(serial), mode, KeyStore(keys, "lab."), out / "lab.db",
                      child_ds={dns.name.from_text("iem.lab."): m_iem["ds"]}, **opts)
    m_root = sign_zone(build_root(serial), mode, KeyStore(keys, "."), out / "root.db",
                       child_ds={dns.name.from_text("lab."): m_lab["ds"]}, **opts)
    _atomic_write(out / "trust-anchor.ds", m_root["ds"] + "\n")
    info = {"mode": mode, "layout": layout, "leaf_order": leaf_order, "hosts": hosts,
            "serial": serial, "zones": {"iem.lab.": m_iem, "lab.": m_lab, ".": m_root}}
    _atomic_write(out / "meta.json", json.dumps(info, indent=1))
    return info


def evolve(out: Path, keys: Path, add_hosts: int, now=None) -> dict:
    """Add hosts to iem.lab. and re-sign, continuing the MTL series (unchanged RRsets keep their leaf)."""
    info = json.loads((Path(out) / "meta.json").read_text())
    return sign_all(info["mode"], info["hosts"] + add_hosts, out, keys, layout=info["layout"],
                    leaf_order=info["leaf_order"], fresh=False, serial=info["serial"] + 1, now=now)


def dataset_hosts(name: str) -> int:
    return DATASETS[name] if name in DATASETS else int(name)

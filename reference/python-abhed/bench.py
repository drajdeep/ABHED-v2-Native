# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""
Benchmarks. Every function writes raw JSON under <results>/ and returns the same data.

  crypto  : zone signing and cold verification cost per mode, with operation counts
  dns     : mixed workload (Zipf-popular names, NXDOMAIN, NODATA) through the validating resolver
  udpfit  : response size per answer class and encoding, against the 1232-byte UDP limit
  churn   : a zone that keeps changing while a resolver keeps querying it
"""
from __future__ import annotations

import hashlib
import json
import random
import statistics as st
import struct
import time
from pathlib import Path

import dns.edns
import dns.flags
import dns.message
import dns.rdatatype as T
from Crypto.Hash import cSHAKE128

from . import mtl, signer
from .authd import AuthServer
from .dnssec import COUNTERS, Key, verify_raw
from .lab import CONFIGS, Lab
from .params import (ABHED_F_COMPACT, ABHED_F_TRIM, ALG_ECDSAP256, ALG_MLDSA44, ALG_MTL,
                     DATASETS, OPT_ABHED, OPT_SIGTAG, ROOT_IP, SLD_IP, TLD_IP, UDP_LIMIT)
from .zone import host_name


def _ms(xs):
    return {"mean": st.mean(xs), "sd": st.stdev(xs) if len(xs) > 1 else 0.0}


def _save(results, name, data):
    p = Path(results) / f"{name}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=1))
    return data


# ---------------------------------------------------------------------------- crypto
def primitives(n=300) -> dict:
    def per(fn, n=n):
        t = time.perf_counter()
        for _ in range(n):
            fn()
        return (time.perf_counter() - t) / n * 1e6
    m, e = Key.generate(ALG_MLDSA44, 256), Key.generate(ALG_ECDSAP256, 256)
    msg = b"x" * 120
    sm, se = m.sign(msg), e.sign(msg)
    blob = b"y" * 112
    return {"mldsa44_sign_us": per(lambda: m.sign(msg)),
            "mldsa44_verify_us": per(lambda: verify_raw(ALG_MLDSA44, m.pub, msg, sm)),
            "ecdsa_sign_us": per(lambda: e.sign(msg)),
            "ecdsa_verify_us": per(lambda: verify_raw(ALG_ECDSAP256, e.pub, msg, se)),
            "cshake128_python_us": per(lambda: cSHAKE128.new(data=blob, custom=b"MTLINT").read(16), 3000),
            "shake128_native_us": per(lambda: hashlib.shake_128(blob).digest(16), 3000)}


def _verify_bundle(path: Path, keys: dict):
    """Cold verification of every RRSIG in a bundle, the way a validator with no cache would."""
    import sqlite3
    db = sqlite3.connect(path)
    sl = db.execute("SELECT v FROM meta WHERE k='signed_ladder'").fetchone()[0]
    rows = db.execute("SELECT s.hdr, s.body, r.name, r.type FROM sig s JOIN rr r "
                      "ON r.name=s.name AND r.type=s.type").fetchall()
    srv = AuthServer(path)
    import dns.name
    from .dnssec import signing_data
    items = []
    for hdr, body, name, t in rows:
        rrs = srv._rr(dns.name.from_text(name), t)
        items.append((bytes(hdr), bytes(body), signing_data(rrs, bytes(hdr), rrs.ttl)))
    t0 = time.perf_counter()
    ladder = None
    if sl:
        s, _ = mtl.SignedLadder.from_bytes(bytes(sl))
        assert any(verify_raw(ALG_MTL, k, s.ladder.to_bytes(), s.signature) for k in keys[ALG_MTL])
        ladder = s.ladder
    for hdr, body, data in items:
        alg = hdr[2]
        if alg == ALG_MTL:
            c, _ = mtl.Condensed.from_bytes(body)
            assert mtl.verify_path(data, c.sid, c.rand, c.leaf, c.sibs, ladder)
        else:
            assert any(verify_raw(alg, k, data, body) for k in keys[alg])
    stored = sum(len(b) for _, b, _ in items) + len(sl)
    return time.perf_counter() - t0, stored, len(items)


CRYPTO_VARIANTS = {"ecdsa": dict(mode="ecdsa"), "split": dict(mode="split"),
                   "mldsa44": dict(mode="mldsa44"),
                   "mtl": dict(mode="mtl", layout="csk", leaf_order="hot-last")}


def crypto(results, work, datasets=("small", "medium", "large"), trials=3) -> dict:
    out = {"primitives": primitives(), "rows": []}
    for ds in datasets:
        for name, v in CRYPTO_VARIANTS.items():
            sign, verify, per = [], [], None
            for t in range(trials):
                d = Path(work) / "crypto" / name
                info = signer.sign_all(v["mode"], DATASETS[ds], d / "zones", d / "keys",
                                       layout=v.get("layout", "csk"),
                                       leaf_order=v.get("leaf_order", "hot-last"))
                z = info["zones"]["iem.lab."]
                kd = d / "keys" / "iem.lab"
                keys = {}
                for f in kd.glob("*sk.json"):
                    k = Key.from_json(json.loads(f.read_text()))
                    keys.setdefault(k.alg, []).append(k.pub)
                h0, v0 = mtl.COUNTERS["hashes"], COUNTERS["mldsa_verify"]
                vs, stored, n = _verify_bundle(d / "zones" / "iem.lab.db", keys)
                sign.append(z["sign_s"] * 1000); verify.append(vs * 1000)
                per = dict(rrsigs=n, mldsa_signs=z["mldsa_signs"], ecdsa_signs=z["ecdsa_signs"],
                           sign_hashes=z["hashes"], verify_hashes=mtl.COUNTERS["hashes"] - h0,
                           mldsa_verifies=COUNTERS["mldsa_verify"] - v0, stored_sig_bytes=stored)
            out["rows"].append(dict(dataset=ds, variant=name, sign_ms=_ms(sign),
                                    verify_ms=_ms(verify), **per))
            print(f"crypto {ds:7s} {name:8s} sign {st.mean(sign):9.1f} ms  verify {st.mean(verify):9.1f} ms", flush=True)
    return _save(results, "crypto", out)


# ---------------------------------------------------------------------------- workload
class Workload:
    """80% A for Zipf-popular hosts, 10% NXDOMAIN, 5% NODATA (AAAA), 5% other names/types."""

    def __init__(self, hosts: int, seed: int, zipf_s: float = 1.0, recent: range | None = None):
        self.rng = random.Random(seed)
        self.hosts = hosts
        ranks = list(range(1, hosts + 1))
        self.order = ranks[:]
        self.rng.shuffle(self.order)
        self.cum, acc = [], 0.0
        for r in ranks:
            acc += 1.0 / r ** zipf_s
            self.cum.append(acc)
        self.recent = recent
        self.other = [("www.iem.lab.", T.A), ("mail.iem.lab.", T.A), ("iem.lab.", T.MX),
                      ("iem.lab.", T.TXT), ("www.lab.", T.A), ("iem.lab.", T.NS)]

    def host(self) -> str:
        return host_name(self.order[self.rng.choices(range(self.hosts), cum_weights=self.cum)[0]])

    def next(self):
        x = self.rng.random()
        if self.recent and x < 0.30:
            return host_name(self.rng.choice(self.recent)), T.A, "new"
        if x < 0.80:
            return self.host(), T.A, "A"
        if x < 0.90:
            # a name that sorts between two existing hosts, so the covering NSEC is a typical one
            return self.host()[:-9] + "x.iem.lab.", T.A, "NXDOMAIN"
        if x < 0.95:
            return self.host(), T.AAAA, "NODATA"
        n, t = self.rng.choice(self.other)
        return n, t, "other"


def _delta(a, b):
    return {k: b[k] - a[k] for k in b}


def dns_workload(results, work, configs=None, dataset="medium", trials=5, queries=500, live=False,
        rtt_ms=0.0) -> dict:
    out = {"dataset": dataset, "queries": queries, "trials": trials, "live": live,
           "rtt_ms": rtt_ms, "rows": []}
    hosts = DATASETS[dataset]
    for name in configs or list(CONFIGS):
        lab = Lab(Path(work) / "dns", name, hosts, fresh=False)
        per_trial, fails = [], 0
        for t in range(trials):
            r = lab.resolver(live=live, rtt_ms=rtt_ms)
            w = Workload(hosts, seed=1000 + t)
            s0, lat, udp_only, upstream = r.snapshot(), [], 0, 0
            for _ in range(queries):
                qn, qt, _kind = w.next()
                a, t0 = r.snapshot(), time.perf_counter()
                try:
                    res = r.resolve(qn, qt)
                except Exception:
                    fails += 1
                    continue
                lat.append((time.perf_counter() - t0) * 1000)
                d = _delta(a, r.snapshot())
                if not res["from_cache"]:
                    upstream += 1
                    udp_only += d["tcp"] == 0
            d = _delta(s0, r.snapshot())
            lat.sort()
            per_trial.append(dict(d, upstream_queries=upstream,
                                  udp_only_rate=udp_only / max(upstream, 1),
                                  p50_ms=lat[len(lat) // 2], p95_ms=lat[int(len(lat) * 0.95)],
                                  crypto_ms=d["crypto_s"] * 1000, **r.cache_bytes()))
        row = {"config": name, "label": CONFIGS[name]["label"], "failures": fails}
        for k in per_trial[0]:
            row[k] = _ms([p[k] for p in per_trial])
        out["rows"].append(row)
        print(f"dns {name:13s} bytes_rx {row['bytes_rx']['mean']/1024:8.1f} KiB  tcp {row['tcp']['mean']:6.1f}"
              f"  round-trips {row['round_trips']['mean']:7.1f}  udp-only {row['udp_only_rate']['mean']*100:5.1f}%"
              f"  fail {fails}", flush=True)
    return _save(results, f"dns_{dataset}" + ("_live" if live else ""), out)


# ---------------------------------------------------------------------------- UDP fit
def _q(name, t, opts=None):
    return dns.message.make_query(name, t, want_dnssec=True, payload=UDP_LIMIT,
                                  options=opts or []).to_wire()


def udpfit(results, work, dataset="large", samples=200) -> dict:
    hosts = DATASETS[dataset]
    rng = random.Random(7)
    names = [host_name(rng.randrange(1, hosts + 1)) for _ in range(samples)]
    nx = [n[:-9] + "x.iem.lab." for n in names]      # sorts right after an existing host
    classes = {"A (positive)": (SLD_IP, [(n, T.A) for n in names]),
               "NODATA": (SLD_IP, [(n, T.AAAA) for n in names]),
               "NXDOMAIN": (SLD_IP, [(n, T.A) for n in nx]),
               "Referral + DS": (TLD_IP, [(n, T.A) for n in names[:20]]),
               "DNSKEY": (SLD_IP, [("iem.lab.", T.DNSKEY)])}
    encodings = [
        ("ECDSA P-256", "ecdsa", None),
        ("ML-DSA-44", "mldsa44", None),
        ("MTL full signature (base draft)", "mtl-base", None),
        ("MTL SigTag, first contact (dedup)", "mtl-sigtag", "probe"),
        ("MTL SigTag condensed", "mtl-sigtag", "tag"),
        ("MTL SigTag condensed + hot-last leaves", "mtl-abhed", "tag"),
        ("MTL ABHED compact + hot-last leaves", "mtl-abhed", "abhed"),
    ]
    out = {"dataset": dataset, "limit": UDP_LIMIT, "rows": []}
    for label, cfg, how in encodings:
        lab = Lab(Path(work) / "udpfit", cfg, hosts, fresh=False)
        for cls, (ip, qs) in classes.items():
            srv = lab.servers[ip]
            opts = None
            if how:
                tag = b"" if how == "probe" else srv.sid + struct.pack(">Q", srv.n - 1)
                opts = [dns.edns.GenericOption(OPT_SIGTAG, tag)]
                if how == "abhed":
                    opts.append(dns.edns.GenericOption(OPT_ABHED, bytes([ABHED_F_TRIM | ABHED_F_COMPACT])))
            sizes = [len(srv.handle(_q(n, t, opts), True)) for n, t in qs]
            out["rows"].append(dict(encoding=label, cls=cls, min=min(sizes), mean=st.mean(sizes),
                                    max=max(sizes), fit=sum(s <= UDP_LIMIT for s in sizes) / len(sizes)))
        print("udpfit", label, flush=True)
    out["projection"] = projection(out)
    return _save(results, f"udpfit_{dataset}", out)


def projection(u: dict) -> list:
    """CALCULATED worst-case NXDOMAIN size for bigger zones (tree height k = log2 of leaf count).
    Fixed part = measured ECDSA NXDOMAIN response minus its three 64-byte signatures, plus the
    4-byte echoed option. A condensed signature field is 77 + 16h bytes, a compact one 27 + 16h."""
    ec = next(r for r in u["rows"] if r["encoding"] == "ECDSA P-256" and r["cls"] == "NXDOMAIN")
    fixed = ec["max"] - 3 * 64 + 4
    rows = []
    for k in (10, 14, 15, 17, 20, 24, 27, 30):
        rows.append({"k": k, "leaves": 2 ** k,
                     "condensed_canonical": fixed + 3 * (77 + 16 * k),
                     "condensed_hot_last": fixed + 77 + (77 + 32) + (77 + 16 * k),
                     "compact_hot_last": fixed + 27 + (27 + 32) + (27 + 16 * k)})
    return rows


# ---------------------------------------------------------------------------- churn
def churn(results, work, hosts=1000, steps=20, alpha=10, rho=50,
          configs=("mldsa44-tcp", "mtl-base-tcp", "mtl-sigtag", "mtl-abhed")) -> dict:
    """Each step: alpha new hosts are added and the zone is re-signed; then the same resolver
    (answer cache off = every query reaches the authoritative servers) sends rho queries,
    30% of them for names added in the last 3 steps."""
    out = {"hosts": hosts, "steps": steps, "alpha": alpha, "rho": rho, "rows": []}
    for name in configs:
        lab = Lab(Path(work) / "churn", name, hosts)
        r = lab.resolver(answer_cache=False)
        w = Workload(hosts, seed=42)
        for _ in range(rho):                                  # warm-up before any change
            qn, qt, _k = w.next(); r.resolve(qn, qt)
        per, n = [], hosts
        for step in range(steps):
            lab.evolve(alpha)
            n += alpha
            w.recent = range(max(hosts + 1, n - 3 * alpha + 1), n + 1)
            a = r.snapshot()
            fails = 0
            for _ in range(rho):
                qn, qt, _k = w.next()
                try:
                    r.resolve(qn, qt)
                except Exception:
                    fails += 1
            d = _delta(a, r.snapshot())
            per.append(dict(step=step + 1, tcp=d["tcp"], udp=d["udp"], bytes_rx=d["bytes_rx"],
                            round_trips=d["round_trips"], retries=d["retries"],
                            mldsa_verifies=d["mldsa_verifies"], failures=fails))
        tot = {k: sum(p[k] for p in per) for k in per[0] if k != "step"}
        q = steps * rho
        out["rows"].append(dict(config=name, label=CONFIGS[name]["label"], per_step=per,
                                tcp_per_100q=tot["tcp"] / q * 100, bytes_per_query=tot["bytes_rx"] / q,
                                round_trips_per_query=tot["round_trips"] / q,
                                mldsa_verifies_per_100q=tot["mldsa_verifies"] / q * 100,
                                failures=tot["failures"]))
        print(f"churn {name:13s} tcp/100q {tot['tcp']/q*100:6.1f}  bytes/q {tot['bytes_rx']/q:7.0f}"
              f"  rt/q {tot['round_trips']/q:5.2f}  fail {tot['failures']}", flush=True)
    return _save(results, "churn", out)

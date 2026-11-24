# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""Command line:  python -m abhed <command> ...   (see docs/USAGE.md)"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__, bench, signer
from .lab import CONFIGS, Lab
from .params import DATASETS, ROOT_IP


def _demo(a):
    qs = [("host000042.iem.lab.", "A"), ("host000007.iem.lab.", "A"), ("nope.iem.lab.", "A"),
          ("www.iem.lab.", "AAAA"), ("iem.lab.", "MX")]
    print(f"{'configuration':14s} " + " ".join(f"{q.split('.')[0][:10]+'/'+t:>16s}" for q, t in qs)
          + "   TCP  ladders")
    for c in (a.configs or CONFIGS):
        lab = Lab(a.work, c, DATASETS[a.dataset], fresh=False)
        r = lab.resolver()
        cells = []
        for q, t in qs:
            b = dict(r.s)
            x = r.resolve(q, t)
            via = "TCP" if r.s["tcp"] > b["tcp"] else "UDP"
            cells.append(f"{x['rcode'][:4]} {x['answer_bytes']:5d}B {via}")
        print(f"{c:14s} " + " ".join(f"{c_:>16s}" for c_ in cells)
              + f"   {r.s['tcp']:3d}  {r.s['ladders_verified']:3d}")
    print("\nEvery answer above was validated from the trust anchor (status SECURE).\n"
          "TCP/UDP: whether resolving that name needed any TCP exchange. For the first name this\n"
          "includes building the chain of trust (DNSKEY fetches).")


def _evolve_demo(a):
    lab = Lab(a.work, "mtl-abhed", 100)
    r = lab.resolver(answer_cache=False)
    def show(what, name):
        b = dict(r.s)
        x = r.resolve(name, "A")
        print(f"  {what:46s} {x['status']}  {x['answer_bytes']:5d} B  "
              f"{'TCP' if r.s['tcp'] > b['tcp'] else 'UDP'}  ladders verified so far: {r.s['ladders_verified']}")
    print("1. cold resolver, zone with 100 hosts"); show("host000010 (first query)", "host000010.iem.lab.")
    lab.evolve(10)
    print("2. zone re-signed with 10 new hosts (new ladder, same series)")
    show("host000010 (old leaf, verified with OLD ladder)", "host000010.iem.lab.")
    show("host000105 (new leaf, needs the new ladder)", "host000105.iem.lab.")
    show("host000106 (new leaf, ladder now cached)", "host000106.iem.lab.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="abhed", description=f"ABHED-v2 {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sign", help="sign root, lab. and iem.lab.")
    s.add_argument("--mode", choices=signer.MODES, default="mtl")
    s.add_argument("--dataset", default="small", help="small|medium|large|xl or a host count")
    s.add_argument("--layout", choices=("csk", "split"), default="csk")
    s.add_argument("--leaf-order", choices=("hot-last", "canonical"), default="hot-last")
    s.add_argument("--out", default="zones"); s.add_argument("--keys", default="keys")

    s = sub.add_parser("evolve", help="add hosts and re-sign, continuing the MTL series")
    s.add_argument("--add", type=int, default=10)
    s.add_argument("--out", default="zones"); s.add_argument("--keys", default="keys")

    s = sub.add_parser("authd", help="serve one zone bundle")
    s.add_argument("--bundle", required=True); s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=53); s.add_argument("--rtt-ms", type=float, default=0)

    s = sub.add_parser("resolverd", help="validating resolver for stubs (dig)")
    s.add_argument("--anchor", default="zones/trust-anchor.ds"); s.add_argument("--root-ip", default=ROOT_IP)
    s.add_argument("--profile", choices=("base", "sigtag", "abhed"), default="abhed")
    s.add_argument("--no-tcp-first", action="store_true")
    s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=53)
    s.add_argument("--map", action="append", default=[], help="ip=host:port (run without Docker)")

    s = sub.add_parser("resolve", help="resolve + validate names against running servers")
    s.add_argument("names", nargs="+", help="name[/TYPE]")
    s.add_argument("--anchor", default="zones/trust-anchor.ds"); s.add_argument("--root-ip", default=ROOT_IP)
    s.add_argument("--profile", choices=("base", "sigtag", "abhed"), default="abhed")
    s.add_argument("--map", action="append", default=[])

    for name in ("demo", "demo-evolve", "bench-crypto", "bench-dns", "bench-udpfit", "bench-churn",
                 "bench-all", "report"):
        s = sub.add_parser(name)
        s.add_argument("--work", default="work"); s.add_argument("--results", default="results")
        s.add_argument("--dataset", default="medium")
        s.add_argument("--datasets", nargs="+", default=["small", "medium", "large"])
        s.add_argument("--configs", nargs="+")
        s.add_argument("--trials", type=int, default=5); s.add_argument("--queries", type=int, default=500)
        s.add_argument("--live", action="store_true"); s.add_argument("--rtt-ms", type=float, default=0)
        s.add_argument("--steps", type=int, default=20); s.add_argument("--alpha", type=int, default=10)
        s.add_argument("--rho", type=int, default=50)

    a = p.parse_args(argv)
    amap = {}
    for m in getattr(a, "map", []):
        ip, hp = m.split("=")
        h, port = hp.rsplit(":", 1)
        amap[ip] = (h, int(port))

    if a.cmd == "sign":
        info = signer.sign_all(a.mode, signer.dataset_hosts(a.dataset), Path(a.out), Path(a.keys),
                               layout=a.layout, leaf_order=a.leaf_order)
        for zn, z in info["zones"].items():
            extra = f" leaves={z['n']} rungs={z['rungs']}" if "n" in z else ""
            print(f"signed {zn:10s} rrsets={z['rrsets']:6d} ML-DSA signatures={z['mldsa_signs']:6d}"
                  f" time={z['sign_s']*1000:8.1f} ms{extra}")
        print("trust anchor (root DS):", info["zones"]["."]["ds"])
    elif a.cmd == "evolve":
        z = signer.evolve(Path(a.out), Path(a.keys), a.add)["zones"]["iem.lab."]
        print(f"iem.lab. now has {z['n']} leaves, {z['new_leaves']} new, ML-DSA signatures this run: {z['mldsa_signs']}")
    elif a.cmd == "authd":
        from .authd import AuthServer, serve
        srv = AuthServer(a.bundle)
        serve(srv, a.host, a.port, a.rtt_ms)
        print(f"authd: {srv.meta['origin']} mode={srv.meta['mode']} on {a.host}:{a.port}", flush=True)
        import signal
        signal.signal(signal.SIGHUP, lambda *_: (srv.reload(), print("reloaded", flush=True)))
        while True:
            time.sleep(3600)
    elif a.cmd in ("resolverd", "resolve"):
        from .resolver import NetTransport, Resolver
        anchor = Path(a.anchor).read_text().strip()
        if a.cmd == "resolverd":
            from . import resolverd
            r = Resolver(NetTransport(amap), a.root_ip, anchor, profile=a.profile,
                         tcp_first=not a.no_tcp_first)
            resolverd.serve(r, a.host, a.port)
            print(f"resolverd: profile={a.profile} on {a.host}:{a.port}", flush=True)
            while True:
                time.sleep(3600)
        r = Resolver(NetTransport(amap), a.root_ip, anchor, profile=a.profile, tcp_first=True)
        rc = 0
        for item in a.names:
            name, _, t = item.partition("/")
            b = dict(r.s)
            try:
                x = r.resolve(name if name.endswith(".") else name + ".", t or "A")
                ans = "; ".join(rr.to_text() for rs in x["answer"] for rr in rs) or "-"
                print(f"{x['status']}  {x['rcode']:8s} {name} {t or 'A'}  [{ans}]  "
                      f"udp={r.s['udp']-b['udp']} tcp={r.s['tcp']-b['tcp']} bytes={r.s['bytes_rx']-b['bytes_rx']}")
            except Exception as e:
                rc = 1
                print(f"BOGUS   {name}: {e}")
        sys.exit(rc)
    elif a.cmd == "demo":
        _demo(a)
    elif a.cmd == "demo-evolve":
        _evolve_demo(a)
    elif a.cmd == "bench-crypto":
        bench.crypto(a.results, a.work, a.datasets, min(a.trials, 3))
    elif a.cmd == "bench-dns":
        bench.dns_workload(a.results, a.work, a.configs, a.dataset, a.trials, a.queries, a.live, a.rtt_ms)
    elif a.cmd == "bench-udpfit":
        for ds in a.datasets:
            bench.udpfit(a.results, a.work, ds)
    elif a.cmd == "bench-churn":
        bench.churn(a.results, a.work, steps=a.steps, alpha=a.alpha, rho=a.rho)
    elif a.cmd == "bench-all":
        from . import report
        report.environment(a.results)
        bench.crypto(a.results, a.work, a.datasets, min(a.trials, 3))
        for ds in a.datasets:
            bench.udpfit(a.results, a.work, ds)
            bench.dns_workload(a.results, a.work, a.configs, ds, a.trials, a.queries)
        bench.dns_workload(a.results, a.work, a.configs, "medium", 3, 200, live=True, rtt_ms=a.rtt_ms or 20)
        bench.churn(a.results, a.work, steps=a.steps, alpha=a.alpha, rho=a.rho)
        report.build(a.results)
    elif a.cmd == "report":
        from . import report
        report.build(a.results)


if __name__ == "__main__":
    main()

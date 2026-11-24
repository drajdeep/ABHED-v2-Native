# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""Glue used by tests, benchmarks and the CLI: named configurations and in-process labs."""
from __future__ import annotations

from pathlib import Path

from . import signer
from .authd import AuthServer, serve
from .params import ROOT_IP, SLD_IP, TLD_IP
from .resolver import DirectTransport, NetTransport, Resolver

BUNDLES = {ROOT_IP: "root.db", TLD_IP: "lab.db", SLD_IP: "iem.lab.db"}

# name -> zone signing options + resolver behaviour
CONFIGS = {
    "ecdsa":        dict(mode="ecdsa", profile="base", tcp_first=False,
                         label="ECDSA P-256 (classical reference)"),
    "split":        dict(mode="split", profile="base", tcp_first=True,
                         label="ML-DSA-44 KSK + ECDSA ZSK (algorithm split)"),
    "mldsa44":      dict(mode="mldsa44", profile="base", tcp_first=False,
                         label="ML-DSA-44, UDP then TCP"),
    "mldsa44-tcp":  dict(mode="mldsa44", profile="base", tcp_first=True,
                         label="ML-DSA-44, TCP first"),
    "mtl-base":     dict(mode="mtl", layout="split", leaf_order="canonical", profile="base",
                         tcp_first=False, label="MTL base draft, UDP then TCP"),
    "mtl-base-tcp": dict(mode="mtl", layout="split", leaf_order="canonical", profile="base",
                         tcp_first=True, label="MTL base draft, TCP first"),
    "mtl-sigtag":   dict(mode="mtl", layout="split", leaf_order="canonical", profile="sigtag",
                         tcp_first=True, label="MTL + SigTag extension"),
    "mtl-abhed":    dict(mode="mtl", layout="csk", leaf_order="hot-last", profile="abhed",
                         tcp_first=True, label="MTL + SigTag + ABHED UDP-first profile"),
}


def zone_variant(cfg: dict) -> str:
    return "-".join(x for x in (cfg["mode"], cfg.get("layout"), cfg.get("leaf_order")) if x)


class Lab:
    """Signed zones on disk + authoritative servers in this process."""

    def __init__(self, workdir, config: str, hosts: int, fresh: bool = True):
        self.cfg = CONFIGS[config]
        self.dir = Path(workdir) / zone_variant(self.cfg) / str(hosts)
        self.zones, self.keys = self.dir / "zones", self.dir / "keys"
        if fresh or not (self.zones / "meta.json").exists():
            self.info = signer.sign_all(self.cfg["mode"], hosts, self.zones, self.keys,
                                        layout=self.cfg.get("layout", "csk"),
                                        leaf_order=self.cfg.get("leaf_order", "hot-last"))
        self.servers = {ip: AuthServer(self.zones / f) for ip, f in BUNDLES.items()}
        self.anchor = (self.zones / "trust-anchor.ds").read_text().strip()
        self._net = None

    def evolve(self, add_hosts: int):
        signer.evolve(self.zones, self.keys, add_hosts)
        for s in self.servers.values():
            s.reload()

    def resolver(self, live: bool = False, rtt_ms: float = 0.0, **kw) -> Resolver:
        if live:
            if self._net is None:
                self._net = {ip: serve(s, "127.0.0.1", 0, rtt_ms)[0].server_address
                             for ip, s in self.servers.items()}
            transport = NetTransport(self._net)
        else:
            transport = DirectTransport(self.servers)
        opts = dict(profile=self.cfg["profile"], tcp_first=self.cfg["tcp_first"])
        opts.update(kw)
        return Resolver(transport, ROOT_IP, self.anchor, **opts)

# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""Unsigned zone model, the three lab zones (root -> lab. -> iem.lab.) and the NSEC chain."""
from __future__ import annotations

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype as T
import dns.rrset

from .params import ROOT_IP, ROOT_NS, SLD_IP, SLD_NS, TLD_IP, TLD_NS, TTL


def N(text: str) -> dns.name.Name:
    return dns.name.from_text(text).canonicalize()


class Zone:
    def __init__(self, origin: str):
        self.origin = N(origin)
        self.rrsets: dict = {}
        self.cuts: set = set()

    def add(self, name, rdtype, *items, ttl=TTL):
        name = N(name) if isinstance(name, str) else name
        key = (name, rdtype)
        rrs = self.rrsets.get(key) or dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
        for t in items:
            rrs.add(dns.rdata.from_text(dns.rdataclass.IN, rdtype, t) if isinstance(t, str) else t, ttl)
        self.rrsets[key] = rrs
        if rdtype == T.NS and name != self.origin:
            self.cuts.add(name)

    def occluded(self, name) -> bool:               # strictly below a delegation -> glue
        return any(name != c and name.is_subdomain(c) for c in self.cuts)

    def auth_names(self) -> list:
        return sorted({n for (n, _) in self.rrsets if not self.occluded(n)})

    def signable(self, name, rdtype) -> bool:
        if self.occluded(name) or rdtype == T.RRSIG:
            return False
        if name in self.cuts:
            return rdtype in (T.DS, T.NSEC)
        return True


def _soa(ns, serial):
    return f"{ns} hostmaster.iem.lab. {serial} 7200 3600 1209600 300"


def build_root(serial):
    z = Zone(".")
    z.add(".", T.SOA, _soa(ROOT_NS, serial))
    z.add(".", T.NS, ROOT_NS)
    z.add("lab.", T.NS, TLD_NS)
    z.add(ROOT_NS, T.A, ROOT_IP)
    z.add(TLD_NS, T.A, TLD_IP)
    return z


def build_lab(serial):
    z = Zone("lab.")
    z.add("lab.", T.SOA, _soa(TLD_NS, serial))
    z.add("lab.", T.NS, TLD_NS)
    z.add(TLD_NS, T.A, TLD_IP)
    z.add(ROOT_NS, T.A, ROOT_IP)
    z.add("www.lab.", T.A, "10.20.0.80")
    z.add("iem.lab.", T.NS, SLD_NS)
    z.add(SLD_NS, T.A, SLD_IP)
    return z


def host_name(i: int) -> str:
    return f"host{i:06d}.iem.lab."


def build_iem(serial, hosts):
    z = Zone("iem.lab.")
    z.add("iem.lab.", T.SOA, _soa(SLD_NS, serial))
    z.add("iem.lab.", T.NS, SLD_NS)
    z.add(SLD_NS, T.A, SLD_IP)
    z.add("iem.lab.", T.MX, "10 mail.iem.lab.")
    z.add("iem.lab.", T.TXT, '"IEM lab zone - ABHED-v2 PQC DNSSEC testbed"')
    z.add("www.iem.lab.", T.A, "10.53.0.80")
    z.add("mail.iem.lab.", T.A, "10.53.0.25")
    for i in range(1, hosts + 1):
        z.add(host_name(i), T.A, f"10.{54 + i // 65536}.{(i // 256) % 256}.{i % 256}")
    return z


def add_nsec_chain(z: Zone):
    names = z.auth_names()
    by_name: dict = {}
    for (n, t) in z.rrsets:
        by_name.setdefault(n, set()).add(t)
    for i, n in enumerate(names):
        types = set(by_name[n]) - {T.NSEC}
        if n in z.cuts:
            types &= {T.NS, T.DS}
        types |= {T.RRSIG, T.NSEC}
        nxt = names[(i + 1) % len(names)]
        z.rrsets.pop((n, T.NSEC), None)
        z.add(n, T.NSEC, f"{nxt.to_text()} " + " ".join(T.to_text(t) for t in sorted(types)), ttl=300)

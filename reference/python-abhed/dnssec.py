# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""Keys, signing data (RFC 4034 3.1.8.1) and raw signature primitives."""
from __future__ import annotations

import hashlib
import struct
import time

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)

from .params import ALG_ECDSAP256, ALG_MLDSA44, ALG_MTL, MLDSA_CTX

MLDSA_NAME = "ML-DSA-44"
COUNTERS = {"mldsa_sign": 0, "mldsa_verify": 0, "ecdsa_sign": 0, "ecdsa_verify": 0,
            "crypto_s": 0.0}
_verifier = None


def _mldsa_verify(pub: bytes, data: bytes, sig: bytes) -> bool:
    global _verifier
    if _verifier is None:
        _verifier = oqs.Signature(MLDSA_NAME)
    try:
        return bool(_verifier.verify_with_ctx_str(data, sig, MLDSA_CTX, pub))
    except Exception:
        return False


def verify_raw(alg: int, pub: bytes, data: bytes, sig: bytes) -> bool:
    """Verify an underlying signature (for ALG_MTL the underlying scheme is ML-DSA-44)."""
    t0 = time.perf_counter()
    try:
        if alg == ALG_ECDSAP256:
            COUNTERS["ecdsa_verify"] += 1
            if len(pub) != 64 or len(sig) != 64:
                return False
            try:
                key = ec.EllipticCurvePublicNumbers(int.from_bytes(pub[:32], "big"),
                                                    int.from_bytes(pub[32:], "big"),
                                                    ec.SECP256R1()).public_key()
                key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                                int.from_bytes(sig[32:], "big")),
                           data, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                return False
        if alg in (ALG_MLDSA44, ALG_MTL):
            COUNTERS["mldsa_verify"] += 1
            return _mldsa_verify(pub, data, sig)
        return False
    finally:
        COUNTERS["crypto_s"] += time.perf_counter() - t0


class Key:
    """A DNSSEC key pair. alg is the DNSKEY algorithm number; flags 256 (ZSK) or 257 (KSK/CSK)."""

    def __init__(self, alg: int, flags: int, pub: bytes, priv: bytes):
        self.alg, self.flags, self.pub, self.priv = alg, flags, pub, priv
        self._signer = None

    @classmethod
    def generate(cls, alg: int, flags: int) -> "Key":
        if alg == ALG_ECDSAP256:
            k = ec.generate_private_key(ec.SECP256R1())
            n = k.public_key().public_numbers()
            return cls(alg, flags, n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big"),
                       k.private_numbers().private_value.to_bytes(32, "big"))
        s = oqs.Signature(MLDSA_NAME)
        pub = s.generate_keypair()
        return cls(alg, flags, bytes(pub), bytes(s.export_secret_key()))

    def sign(self, data: bytes) -> bytes:
        if self.alg == ALG_ECDSAP256:
            if self._signer is None:
                self._signer = ec.derive_private_key(int.from_bytes(self.priv, "big"),
                                                     ec.SECP256R1())
            COUNTERS["ecdsa_sign"] += 1
            r, s = decode_dss_signature(self._signer.sign(data, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if self._signer is None:
            self._signer = oqs.Signature(MLDSA_NAME, self.priv)
        COUNTERS["mldsa_sign"] += 1
        return bytes(self._signer.sign_with_ctx_str(data, MLDSA_CTX))

    def dnskey(self):
        w = struct.pack(">HBB", self.flags, 3, self.alg) + self.pub
        return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.DNSKEY, w, 0, len(w))

    def tag(self) -> int:
        return dns.dnssec.key_id(self.dnskey())

    def to_json(self):
        return {"alg": self.alg, "flags": self.flags, "pub": self.pub.hex(), "priv": self.priv.hex()}

    @classmethod
    def from_json(cls, d):
        return cls(d["alg"], d["flags"], bytes.fromhex(d["pub"]), bytes.fromhex(d["priv"]))


def ds_digest(owner: dns.name.Name, dnskey) -> bytes:
    return hashlib.sha256(owner.canonicalize().to_wire() + dnskey.to_wire()).digest()


def ds_text(owner: dns.name.Name, dnskey) -> str:
    return f"{dns.dnssec.key_id(dnskey)} {int(dnskey.algorithm)} 2 {ds_digest(owner, dnskey).hex()}"


def rrsig_header_wire(type_covered, alg, labels, orig_ttl, expiration, inception, key_tag,
                      signer: dns.name.Name) -> bytes:
    return struct.pack(">HBBIIIH", type_covered, alg, labels, orig_ttl, expiration,
                       inception, key_tag) + signer.canonicalize().to_wire()


def canonical_rrset_wire(rrset: dns.rrset.RRset, orig_ttl: int) -> bytes:
    owner = rrset.name.canonicalize().to_wire()
    out, prev = [], None
    for rd in sorted(rd.to_digestable(dns.name.root) for rd in rrset):
        if rd == prev:
            continue
        prev = rd
        out.append(owner + struct.pack(">HHIH", rrset.rdtype, rrset.rdclass, orig_ttl, len(rd)) + rd)
    return b"".join(out)


def signing_data(rrset, hdr: bytes, orig_ttl: int) -> bytes:
    return hdr + canonical_rrset_wire(rrset, orig_ttl)


def signing_data_from_rrsig(rrset, rrsig) -> bytes:
    hdr = rrsig_header_wire(rrsig.type_covered, int(rrsig.algorithm), rrsig.labels,
                            rrsig.original_ttl, rrsig.expiration, rrsig.inception,
                            rrsig.key_tag, rrsig.signer)
    return hdr + canonical_rrset_wire(rrset, rrsig.original_ttl)


def label_count(name: dns.name.Name) -> int:
    n = len(name.labels) - 1
    if n > 0 and name.labels[0] == b"*":
        n -= 1
    return n


def make_rrsig(hdr: bytes, sig: bytes):
    w = hdr + sig
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.RRSIG, w, 0, len(w))

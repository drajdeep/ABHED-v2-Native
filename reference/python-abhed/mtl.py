# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
# Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
"""
ML-DSA-44-MTL-SHAKE-128 node set, ladder and signature encodings.

Follows draft-kaizer-dnsop-ml-dsa-mtl-dnssec-03 (base) and
draft-hdong-dnsop-ml-dsa-mtl-dnssec-sigtag-ext-01 (condensed MTL-Type 0x02, SigTag):

  H_leaf = cSHAKE128(SID | Randomizer | leaf_index | 0x00 | msg, 128 bits, "", "MTLLEAF")
  H_int  = cSHAKE128(SID | left | right | hash_left | hash_right, 128 bits, "", "MTLINT")
  Condensed signature = Flags(2) SID(32) Randomizer(16) Leaf(8) RungL(8) RungR(8) Count(2) 16*s
  Signed ladder       = Flags(2) SID(32) RungCount(2) 32*r  SigLen(4) ML-DSA-44 signature(2420)
  ML-DSA-44 signs       Flags | SID | RungCount | RungData
  SigTag              = SID | right index of the ladder        (40 octets)

MTL-Type 0xF1 (Private Use range of the MTL Type registry) is ABHED's compact condensed
form; it is only sent to clients that ask for it. See docs/UDP_FIT.md.
"""
from __future__ import annotations

import hmac
import os
import struct
from dataclasses import dataclass, field, replace

from Crypto.Hash import cSHAKE128

HASH_LEN = 16
SID_LEN = 32
RAND_LEN = 16
T_FULL, T_COND, T_COMPACT = 0x01, 0x02, 0xF1
REF_IN_RESPONSE = 0xFF      # compact tag reference: "the ladder carried in this response"
COUNTERS = {"hashes": 0}


def h_leaf(sid: bytes, rand: bytes, index: int, msg: bytes) -> bytes:
    COUNTERS["hashes"] += 1
    return cSHAKE128.new(data=sid + rand + struct.pack(">Q", index) + b"\x00" + msg,
                         custom=b"MTLLEAF").read(HASH_LEN)


def h_int(sid: bytes, left: int, right: int, hl: bytes, hr: bytes) -> bytes:
    COUNTERS["hashes"] += 1
    return cSHAKE128.new(data=sid + struct.pack(">QQ", left, right) + hl + hr,
                         custom=b"MTLINT").read(HASH_LEN)


def rungs_for(n: int) -> list:
    """Index pairs of the binary rung strategy for a node set with n leaves."""
    out, left = [], 0
    while n:
        size = 1 << (n.bit_length() - 1)
        out.append((left, left + size - 1))
        left += size
        n -= size
    return out


def rung_of(leaf: int, n: int):
    for l, r in rungs_for(n):
        if l <= leaf <= r:
            return l, r
    raise IndexError("leaf not covered")


@dataclass
class Ladder:
    sid: bytes
    rungs: list                      # [(left, right, hash)]
    flags: int = 0

    def to_bytes(self) -> bytes:     # exactly the bytes ML-DSA-44 signs
        return (struct.pack(">H", self.flags) + self.sid + struct.pack(">H", len(self.rungs))
                + b"".join(struct.pack(">QQ", l, r) + h for l, r, h in self.rungs))

    @classmethod
    def from_bytes(cls, b: bytes, off: int = 0):
        flags, = struct.unpack_from(">H", b, off); off += 2
        sid = bytes(b[off:off + SID_LEN]); off += SID_LEN
        cnt, = struct.unpack_from(">H", b, off); off += 2
        if cnt == 0 or len(sid) != SID_LEN:
            raise ValueError("bad ladder")
        rungs = []
        for _ in range(cnt):
            l, r = struct.unpack_from(">QQ", b, off); off += 16
            h = bytes(b[off:off + HASH_LEN]); off += HASH_LEN
            if len(h) != HASH_LEN:
                raise ValueError("short ladder")
            rungs.append((l, r, h))
        return cls(sid, rungs, flags), off

    @property
    def n(self) -> int:
        return self.rungs[-1][1] + 1

    @property
    def tag(self) -> bytes:          # SigTag
        return self.sid + struct.pack(">Q", self.n - 1)

    def well_formed(self) -> bool:
        return self.flags == 0 and [(l, r) for l, r, _ in self.rungs] == rungs_for(self.n)

    def lookup(self) -> dict:
        return {(l, r): h for l, r, h in self.rungs}


@dataclass
class Condensed:
    sid: bytes
    rand: bytes
    leaf: int
    rung_left: int
    rung_right: int
    sibs: list = field(default_factory=list)
    flags: int = 0

    def to_bytes(self) -> bytes:
        return (struct.pack(">H", self.flags) + self.sid + self.rand
                + struct.pack(">QQQH", self.leaf, self.rung_left, self.rung_right, len(self.sibs))
                + b"".join(self.sibs))

    @classmethod
    def from_bytes(cls, b: bytes, off: int = 0):
        flags, = struct.unpack_from(">H", b, off); off += 2
        sid = bytes(b[off:off + SID_LEN]); off += SID_LEN
        rand = bytes(b[off:off + RAND_LEN]); off += RAND_LEN
        leaf, rl, rr, cnt = struct.unpack_from(">QQQH", b, off); off += 26
        if cnt > 64 or len(b) < off + cnt * HASH_LEN:
            raise ValueError("bad condensed signature")
        sibs = [bytes(b[off + i * HASH_LEN: off + (i + 1) * HASH_LEN]) for i in range(cnt)]
        return cls(sid, rand, leaf, rl, rr, sibs, flags), off + cnt * HASH_LEN


@dataclass
class SignedLadder:
    ladder: Ladder
    signature: bytes

    def to_bytes(self) -> bytes:
        return self.ladder.to_bytes() + struct.pack(">I", len(self.signature)) + self.signature

    @classmethod
    def from_bytes(cls, b: bytes, off: int = 0):
        ladder, off = Ladder.from_bytes(b, off)
        ln, = struct.unpack_from(">I", b, off); off += 4
        sig = bytes(b[off:off + ln])
        if len(sig) != ln or ln == 0:
            raise ValueError("bad signed ladder")
        return cls(ladder, sig), off + ln


def encode_compact(tag_ref: int, c: Condensed) -> bytes:
    return (bytes([T_COMPACT, tag_ref]) + c.rand + struct.pack(">QB", c.leaf, len(c.sibs))
            + b"".join(c.sibs))


def decode_compact(b: bytes):
    """-> (tag_ref, rand, leaf, sibs)"""
    tag_ref = b[1]
    rand = bytes(b[2:2 + RAND_LEN])
    leaf, cnt = struct.unpack_from(">QB", b, 2 + RAND_LEN)
    off = 2 + RAND_LEN + 9
    if cnt > 64 or len(b) != off + cnt * HASH_LEN:
        raise ValueError("bad compact signature")
    return tag_ref, rand, leaf, [bytes(b[off + i * HASH_LEN: off + (i + 1) * HASH_LEN])
                                 for i in range(cnt)]


def trim(c: Condensed, n_client: int) -> Condensed:
    """Shorten a current authentication path so it ends at the rung of an older ladder."""
    l, r = rung_of(c.leaf, n_client)
    height = (r - l + 1).bit_length() - 1
    return replace(c, rung_left=l, rung_right=r, sibs=c.sibs[:height])


def verify_path(msg: bytes, sid: bytes, rand: bytes, leaf: int, sibs: list, ladder: Ladder) -> bool:
    """True if the path authenticates msg against ANY rung of ladder (backward compatible)."""
    if sid != ladder.sid or leaf >= ladder.n:
        return False
    rungs = ladder.lookup()
    h = h_leaf(sid, rand, leaf, msg)
    l = r = leaf
    i = 0
    while True:
        want = rungs.get((l, r))
        if want is not None:
            return hmac.compare_digest(want, h)
        if i >= len(sibs):
            return False
        size = r - l + 1
        if (l // size) % 2 == 0:
            h = h_int(sid, l, r + size, h, sibs[i]); r += size
        else:
            h = h_int(sid, l - size, r, sibs[i], h); l -= size
        i += 1


class NodeSet:
    """Append-only MTL node set (signer side). Stateful: a SID is never reused."""

    def __init__(self, sid: bytes | None = None):
        self.sid = sid or os.urandom(SID_LEN)
        assert len(self.sid) == SID_LEN
        self.rands: list = []
        self.nodes: dict = {}

    @property
    def count(self) -> int:
        return len(self.rands)

    def _push(self, h: bytes, rand: bytes) -> int:
        i = len(self.rands)
        self.rands.append(rand)
        self.nodes[(i, i)] = h
        l, r, size = i, i, 1
        while (l // size) % 2 == 1:
            nl = l - size
            self.nodes[(nl, r)] = h_int(self.sid, nl, r, self.nodes[(nl, l - 1)], self.nodes[(l, r)])
            l, size = nl, size * 2
        return i

    def append(self, msg: bytes) -> int:
        rand = os.urandom(RAND_LEN)
        return self._push(h_leaf(self.sid, rand, len(self.rands), msg), rand)

    def ladder(self, n: int | None = None) -> Ladder:
        n = self.count if n is None else n
        return Ladder(self.sid, [(l, r, self.nodes[(l, r)]) for l, r in rungs_for(n)])

    def authpath(self, leaf: int) -> Condensed:
        L, R = rung_of(leaf, self.count)
        l = r = leaf
        size, sibs = 1, []
        while (l, r) != (L, R):
            if (l // size) % 2 == 0:
                sibs.append(self.nodes[(r + 1, r + size)]); r += size
            else:
                sibs.append(self.nodes[(l - size, l - 1)]); l -= size
            size *= 2
        return Condensed(self.sid, self.rands[leaf], leaf, L, R, sibs)

    def to_json(self) -> dict:
        return {"sid": self.sid.hex(), "rands": [x.hex() for x in self.rands],
                "leaves": [self.nodes[(i, i)].hex() for i in range(self.count)]}

    @classmethod
    def from_json(cls, d: dict) -> "NodeSet":
        ns = cls(bytes.fromhex(d["sid"]))
        for h, r in zip(d["leaves"], d["rands"]):
            ns._push(bytes.fromhex(h), bytes.fromhex(r))
        return ns

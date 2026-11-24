# Design

## 1. Layers

| Layer | Language | Responsibility |
|---|---|---|
| `libabhed` | C | All cryptography and all MTL encoding/decoding. Bounds-checked parsers. The only allocation on the verify path is the ladder cache. |
| Engine patches | C | Thin glue: Unbound calls `abhed_verify_rrsig`; NSD calls the library to store and compose RRSIGs. |
| `abhed-signzone` | C | Offline batch signer on ldns. Owns the private keys and the MTL series state. |
| `abhedctl`, `abhed-bench` | Go | No cryptography. Generate zones and configuration, drive the signer, read server statistics, build reports. |
| `deploy/*.sh` | Bash | Build, run, test, benchmark. |

## 2. Wire formats

```
Leaf hash      cSHAKE128(SID | Randomizer | leaf_index | 0x00 | msg, 16 bytes, "", "MTLLEAF")
Internal hash  cSHAKE128(SID | left | right | hash_left | hash_right, 16 bytes, "", "MTLINT")
msg            RRSIG RDATA without the signature | canonical RRset      (RFC 4034 §3.1.8.1)

Condensed      Flags(2)=0 | SID(32) | Randomizer(16) | Leaf(8) | RungLeft(8) | RungRight(8)
               | SiblingCount(2) | Siblings(16 each)                          76 + 16·s bytes
Signed ladder  Flags(2)=0 | SID(32) | RungCount(2) | Rungs(Left 8, Right 8, Hash 16)
               | SigLen(4) | ML-DSA-44 signature(2420)                        2460 + 32·r bytes
ML-DSA-44 signs  Flags | SID | RungCount | Rungs      (pure ML-DSA, empty context)
SigTag         SID(32) | right index of the ladder(8)                         40 bytes
```

RRSIG signature field of algorithm ML-DSA-44-MTL-SHAKE-128:

| MTL-Type | Content | Size | Defined by |
|---|---|---|---|
| 0x01 full | condensed + signed ladder | 2537 + 16·s + 32·r | base draft |
| 0x02 condensed | condensed | 77 + 16·s | SigTag draft |
| 0xF1 compact | Randomizer(16), Leaf(8), Count(1), Siblings | 26 + 16·s | ABHED, Private Use range |

EDNS(0) options: SigTag (code 65001, zero to eight 40-byte tags; empty means "supported, none
held") and ABHED (code 65002, one flag byte: 0x01 TRIM, 0x02 COMPACT). Algorithm number, option
codes and types are constants in `lib/libabhed/include/abhed/abhed.h`.

Rungs follow the binary strategy: for N leaves, the roots of the perfect subtrees given by the
binary digits of N, largest first.

## 3. Signer (`abhed-signzone`)

1. Reads the unsigned zone, adds DNSKEY and the NSEC chain.
2. Loads the MTL series from the state directory, or starts one with a fresh random SID.
3. Appends a leaf for every RRset that is new, changed or close to expiry. With `hot-last`,
   apex NSEC, NS, DNSKEY and SOA are appended last, where proofs are shortest.
4. Signs the ladder once with ML-DSA-44.
5. Writes a standard zone file in which every MTL RRSIG is a **full** signature. Any server can
   serve that file as the base draft requires.

## 4. NSD patch (authoritative)

12 files, about 520 lines. New file `abhed_mtl.c`.

- **Load time.** For each MTL RRSIG read from the zone, the signed ladder is interned once per
  zone and the RRSIG is stored in condensed form. Memory per RRSIG drops from about 2.9 kB to
  a few hundred bytes.
- **Query time.** EDNS parsing accepts the SigTag and ABHED options (FORMERR on a bad length
  or more than eight tags). When an MTL RRSIG is written into a response:
  - no SigTag option → full signature;
  - a client tag has the zone's SID and covers the leaf → condensed; with the ABHED flags the
    path is trimmed to the client's rung and encoded compact;
  - no tag matches → one full signature per response, the others condensed (deduplication).
- **Truncation** is NSD's normal behaviour: a response over the UDP limit gets TC=1.
- **Statistics.** New counters in `nsd-control stats` (see `docs/USAGE.md`).

## 5. Unbound patch (validating resolver)

7 files, about 300 lines.

- `validator/val_secalgo.c`: algorithms 18 and MTL are reported as supported;
  `verify_canonrrset` hands them to `abhed_verify_rrsig` together with the signer name taken
  from the signing data.
- `validator/validator.c`: creates the ladder cache; before validating a message it first
  verifies the RRsets whose RRSIG is a full MTL signature, so the ladder is cached before the
  condensed signatures of the same response are checked (needed for deduplication).
- `services/outside_network.c`: when a DNSSEC query is sent for a zone, appends the SigTag
  option with the tags of the ladders cached for that zone, and the ABHED option if enabled.
- `util/config*`: the three new options.

Verification of a full signature checks the Merkle path first (a few hashes) and the ML-DSA-44
signature second, and skips the second step when that exact ladder is already cached. A path is
accepted against any rung of a cached ladder, which is what keeps an old ladder useful after
the zone grows. The ladder cache is process-wide, keyed by signer zone, with at most eight
ladders per zone and LRU eviction across zones.

## 6. Fail-safe behaviour

| Situation | Behaviour |
|---|---|
| Response too large for UDP | TC=1; Unbound retries over TCP. |
| Resolver holds no ladder | Server sends a full signature. |
| Client sends no option | Base-draft behaviour, full signatures. |
| Malformed option | FORMERR. |
| Malformed or oversized signature | Rejected by bounds-checked parsers; sibling and rung counts capped at 64. |
| Forged ladder | Rung layout must match the binary strategy; ML-DSA-44 must verify under a DNSKEY validated through the DS chain. |
| Tampered record, expired signature, wrong signer | Unbound answers SERVFAIL. |
| Signer restarted | Series state is loaded from disk; the SID is never reused for a new series. |

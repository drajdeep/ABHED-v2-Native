# Alignment with IETF work

Checked on 2026-11-12. Internet-Drafts change and expire; check the datatracker before relying
on this page. To report a newer draft version, use the "Draft update" issue template.

## 1. Drafts

| Draft | Version read | Role in ABHED-v2 |
|---|---|---|
| [draft-kaizer-dnsop-ml-dsa-mtl-dnssec](https://datatracker.ietf.org/doc/draft-kaizer-dnsop-ml-dsa-mtl-dnssec/) | -03 (19 Oct 2026) | Base format: hashes, condensed signature, signed ladder, MTL-Type 0x01, binary rung strategy |
| [draft-hdong-dnsop-ml-dsa-mtl-dnssec-sigtag-ext](https://datatracker.ietf.org/doc/draft-hdong-dnsop-ml-dsa-mtl-dnssec-sigtag-ext/) | -01 (27 Oct 2026) | SigTag, EDNS(0) option, MTL-Type 0x02, deduplication, FORMERR rules, retry rules |
| [draft-westerbaan-dnssec-mldsa](https://datatracker.ietf.org/doc/draft-westerbaan-dnssec-mldsa/) | -04 (11 Aug 2026) | ML-DSA-44 as algorithm 18, DNSKEY format, pure ML-DSA with empty context |
| [draft-johani-dnsop-dnssec-alg-experimental-range](https://datatracker.ietf.org/doc/draft-johani-dnsop-dnssec-alg-experimental-range/) | -00 | Source of the lab code point 244 (proposed Private Use range 244–251) |
| [draft-johani-dnsop-dnssec-alg-split](https://datatracker.ietf.org/doc/draft-johani-dnsop-dnssec-alg-split/) | title and abstract only | Motivation for the `split` baseline. ABHED does not implement that draft's mechanism; `split` is simply a zone with an ML-DSA-44 KSK and an ECDSA ZSK. |
| [draft-sheth-pqc-dnssec-strategy](https://datatracker.ietf.org/doc/draft-sheth-pqc-dnssec-strategy/) | -02 | Background |
| draft-harvey-cfrg-mtl-mode, draft-fregly-dnsop-slh-dsa-mtl-dnssec | expired | Used by ABHED-v1. Not used in v2. |

The two MTL drafts were read as rendered summaries of the datatracker pages, not line by line.
Field sizes and rules listed in `docs/DESIGN.md` come from those readings and are checked by the libabhed unit tests.

## 3. Open points in the drafts, and what ABHED chose

| Open point | Choice | How to change it |
|---|---|---|
| Algorithm number for ML-DSA-44-MTL-SHAKE-128 is TBD | 244 | constant in `abhed.h` |
| SigTag EDNS option code is TBD | 65001 (local use range) | constant in `abhed.h` |
| ML-DSA context string for signing the ladder is not stated | empty, as in the ML-DSA draft | `mldsa.c` |
| cSHAKE output length is given as "128" | 128 bits (16 bytes), matching the 16-byte hash fields | `ABHED_HASH_LEN` |
| Order in which RRsets become leaves is not specified | canonical order, or hot-last | `abhed-signzone -l` |
| Truncation behaviour with SigTag is not specified | TC=1 when over the limit, resolver retries over TCP with the same option | NSD default behaviour |
| No test vectors in the drafts | none to check against | see section 5 |

## 4. Mailing-list discussion (DNSOP and pq-dnssec, October–November 2026)

Concerns raised after the PQ DNSSEC interim of 2 October 2026, and what this testbed offers on
each. Read from the public archive; summaries are paraphrased.

| Concern | Raised by | What ABHED-v2 measures or does |
|---|---|---|
| With every RRSIG full, MTL is bigger than ML-DSA-44 and always needs TCP | base draft itself; [Sheth, 26 Oct](http://www.mail-archive.com/dnsop@ietf.org/msg33785.html) | Confirmed: `mtl-base` receives 1,321 KiB against 1,079 KiB for `mldsa44`. Savings only appear with SigTag. |
| Implementation complexity moves into validating resolvers | [Homburg, 28 Oct](http://www.mail-archive.com/dnsop@ietf.org/msg33798.html); [Schlyter, 9 Nov](http://www.mail-archive.com/dnsop@ietf.org/msg33931.html) | The Unbound patch is about 300 lines in 7 files, on top of the shared library. Readers can judge the complexity from a real resolver. |
| Memory use in resolvers and non-validating caches | Homburg | Only the validator's ladder cache is measured. RRset cache memory with condensed signatures is not. |
| Better TCP handling, or a KSK/ZSK algorithm split, may be the simpler path | Schlyter | Both are baselines: `mldsa44-tcp`, `mtl-base-tcp` (TCP first) and `split`. `split` is the cheapest on the wire (81 KiB, 3 TCP) but its ZSK is not post-quantum. |
| Zones with constant dynamic updates and IXFR | [Dyson, 27 Oct](http://www.mail-archive.com/dnsop@ietf.org/msg33793.html) | `abhed-bench churn` re-signs after every batch of changes and continues the series. One ML-DSA signature per batch; resolvers need about 4 TCP queries per 100 new lookups. IXFR itself is not implemented. |
| Online signing | [interim minutes](http://www.mail-archive.com/dnsop@ietf.org/msg33765.html) | Not implemented. A node set per response puts an ML-DSA signature in every answer, so nothing fits UDP (see `docs/UDP_FIT.md`). |
| Feedback wanted from validator implementers | interim minutes | `The Unbound patch is an independent validator implementation written from the drafts. |

## 5. Interoperability finding

Verisign's reference library ([github.com/verisign/MTL](https://github.com/verisign/MTL), read
on 2026-11-12) states in `src/mtl_hash.c` that OpenSSL does not yet support cSHAKE and that it
uses plain SHAKE as a placeholder. ABHED-v2 follows the draft text and implements real cSHAKE128 (checked against the NIST SP 800-185 sample) with
the `MTLLEAF` and `MTLINT` customization strings.

Consequence: hashes produced by ABHED-v2 and by that library are expected to differ, so
signatures will not cross-verify today. This has not been tested end to end. It is worth
raising on the list, because two implementations that both "follow the draft" would not
interoperate, and the drafts contain no test vectors that would reveal it.

## 6. What ABHED adds that is not in any draft

| Addition | Needs a protocol change? |
|---|---|
| CSK layout so the DNSKEY fetch delivers the ladder | No |
| Hot-last leaf placement | No |
| Path trimming | Yes: a client flag (ABHED option 0x01). The result is still a valid draft condensed signature. |
| Compact condensed signature, MTL-Type 0xF1 | Yes: a client flag (0x02) and a private MTL-Type |

These are proposals for discussion. They have had no review outside this project.

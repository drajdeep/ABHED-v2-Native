# Fitting post-quantum DNSSEC answers in UDP

Goal: answers over UDP, TCP as the fallback. Budget: 1,232 bytes.
All sizes are measured on patched NSD by `abhed-bench sizes` unless marked *calculated*.

## 1. Hard limits

| Item | Size | Consequence |
|---|---|---|
| ML-DSA-44 signature | 2,420 bytes | A response carrying one is over the limit. |
| ML-DSA-44 public key | 1,312 bytes | A DNSKEY response is always over the limit. |
| MTL full signature | 2,537 + 16·s + 32·r | Larger than plain ML-DSA-44. |

So a UDP answer can contain only Merkle proofs, and the resolver must already hold a verified
ladder. Two TCP exchanges per zone cannot be avoided: the DNSKEY fetch, and one full signature
for each ladder the resolver has not seen.

## 2. What the SigTag draft gives

10,000-host zone:

| Answer | ML-DSA-44 | MTL full | SigTag condensed |
|---|---|---|---|
| A | 2,522 | 3,039–3,119 | 327–407 |
| NODATA | 5,056 | 6,170–6,250 | 742–822 |
| NXDOMAIN | 7,568 | 9,279–9,359 | 1,135–1,215 |
| Referral + DS | 2,584 | 2,845 | 293 |

It fits, with 17 bytes to spare on NXDOMAIN, which carries three signatures with full-height
proofs. At 100,000 hosts the largest NXDOMAIN is **1,359 bytes: over the limit**.

## 3. The ABHED profile

| Measure | Protocol change? | Effect (measured) |
|---|---|---|
| **Hot-last leaf placement.** The signer appends apex NSEC, NS, DNSKEY and SOA last, where the binary rung strategy gives the shortest proofs. The SOA signature is in every negative answer. | None. Signer policy. | NXDOMAIN 1,135–1,215 → 751–831 (10,000 hosts); largest 1,359 → 879 (100,000 hosts) |
| **Compact encoding** (MTL-Type 0xF1). Drops SID, flags and rung indexes, which a resolver that sent a SigTag can derive. | Client flag + private type | 51 bytes per RRSIG. NXDOMAIN → 598–678; largest 726 at 100,000 hosts |
| **Path trimming.** The server cuts the proof at the rung of the client's (older) ladder. | Client flag | 16 bytes per level the tree has grown |
| **CSK layout.** The MTL key also signs DNSKEY, so the DNSKEY response delivers the ladder. | None | Cold resolver: 8 → 7 TCP queries. See below. |

Compact alone, on a canonical-order zone, is not enough at scale: 1,206 bytes at 100,000 hosts.
Leaf placement is the measure that matters.

**A result that differs from the prototype.** In the Python prototype the resolver fetched
DNSKEY before the data, so the CSK layout removed one TCP exchange per zone. Unbound asks for
the data first and fetches DNSKEY afterwards, so the first data answer per zone is truncated
anyway. On the real engine the CSK layout saves one TCP query, not three.

*Calculated* worst-case NXDOMAIN for larger zones (matches the measurements at 2^14 and 2^17):

| Leaves | Condensed, canonical | Condensed, hot-last | Compact, hot-last |
|---|---|---|---|
| 2^14 | 1,215 | 799 | 649 |
| 2^15 | 1,263 (over) | 815 | 665 |
| 2^20 | 1,503 (over) | 895 | 745 |
| 2^30 | 1,983 (over) | 1,055 | 905 |

## 4. When TCP still happens

| Situation | Result |
|---|---|
| DNSKEY of a PQ zone | Always TCP. |
| First data answer from a zone | Full signature, truncated, one TCP retry; ladder cached. |
| Record newer than the resolver's ladder | Same, once per new ladder. |
| Client sends no SigTag | Every answer, as in the base draft. |

Under churn (zone re-signed 20 times, 50 new lookups after each): 4 TCP queries per 100
lookups with SigTag, 89 without.

## 5. Not adopted

| Idea | Why not |
|---|---|
| Shorten the ML-DSA-44 signature | Breaks FIPS 204 verification. |
| Hashes shorter than 16 bytes | Below the draft's security target. |
| Derive the randomizer | It protects the 16-byte leaf hash against chosen-message collisions. |
| EDNS buffer of 4,096 | Brings back fragmentation. |
| Separate ladder RRset (ABHED-v1) | The SigTag draft covers it. |
| Online signing, one node set per response | An ML-DSA signature in every answer. |

## 6. Worth trying next

- Sharing sibling hashes between the proofs of one response (the two NSEC proofs of an
  NXDOMAIN overlap).
- Making Unbound fetch DNSKEY before the first data query for MTL zones.
- Publishing ladders on a schedule rather than on every change.

# ABHED-v2

### Post-quantum DNSSEC on real engines: ML-DSA-44 and ML-DSA-44 in Merkle Tree Ladder mode, in NSD and Unbound

**Developed by Rajdeep Das, Research Fellow, IEM-UEM, Kolkata, India.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![C](https://img.shields.io/badge/engine-C-blue) ![Go](https://img.shields.io/badge/tooling-Go-00ADD8) ![Bash](https://img.shields.io/badge/deploy-Bash-green)
![Status: experimental](https://img.shields.io/badge/status-experimental-orange) ![Version 2.1.1](https://img.shields.io/badge/version-2.1.1-informational)

**Supported by:** IEM-UEM Group · India Internet Foundation (IIFON) · AIORI, Ministry of Electronics and Information Technology (MeitY), Government of India

---

ABHED-v2 adds two post-quantum DNSSEC algorithms to unmodified upstream releases of
**NSD 4.15.4** (authoritative) and **Unbound 1.26.2** (validating resolver), with a C library,
a C zone signer, Go tooling and Bash deployment around them.

| Algorithm | Number | Specification |
|---|---|---|
| ML-DSA-44 | 18 | draft-westerbaan-dnssec-mldsa-04 |
| ML-DSA-44-MTL-SHAKE-128 | 244 (lab value, TBD in the draft) | draft-kaizer-dnsop-ml-dsa-mtl-dnssec-03 + SigTag extension -01 |

The question it answers: **can a post-quantum DNSSEC answer travel over UDP, with TCP only as
the fallback?**

Measured on the patched engines (zone of 10,000 hosts unless stated; full data in
[`results/REPORT.md`](results/REPORT.md)):

| | ML-DSA-44 | MTL base draft | MTL + SigTag | MTL + SigTag + ABHED profile |
|---|---|---|---|---|
| Positive answer, bytes | 2,522 | 3,039–3,119 | 327–407 | 276–356 |
| NXDOMAIN, bytes | 7,568 | 9,279–9,359 | 1,135–1,215 | 598–678 |
| NXDOMAIN, largest, 100,000 hosts | 7,568 | 9,599 | **1,359 (over 1,232)** | 726 |
| TCP queries, cold resolver, 500 lookups | 328 | 328 | 8 | 7 |
| Bytes received by the resolver | 1,079 KiB | 1,321 KiB | 192 KiB | 147 KiB |
| TCP queries per 100 lookups while the zone is re-signed | 89 | 89 | 4 | 4 |

ECDSA P-256 on the same workload: 70 KiB, no TCP.

- Plain ML-DSA-44 and the MTL base draft need TCP for every answer.
- With the SigTag extension, answers fit in UDP, until the zone is large: at 100,000 hosts
  every NXDOMAIN is over the limit again.
- The ABHED profile (apex records placed last in the tree, compact encoding) keeps NXDOMAIN
  under the limit at every size tested.
- A DNSKEY response never fits: one ML-DSA-44 key is 1,312 bytes.

> **Status: experimental.** These are tested patches on production engines, not audited
> production software. Do not sign or serve real zones with it. See
> [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Components

| Layer | Language | Path | What it is |
|---|---|---|---|
| Crypto and protocol core | C | `lib/libabhed/` | cSHAKE128, MTL node set and ladder, signature encodings, SigTag, ladder cache, ML-DSA-44 via liboqs |
| Zone tools | C | `tools/` | `abhed-keygen`, `abhed-signzone` (stateful batch signer), `abhed-sigdump` |
| Resolver | C | `patches/unbound/` | Unbound 1.26.2: validate algorithms 18 and MTL, ladder cache, send SigTag |
| Authoritative | C | `patches/nsd/` | NSD 4.15.4: store MTL signatures condensed, compose the RRSIG per query, statistics |
| Orchestration, benchmarks | Go | `go/` | `abhedctl` (lab setup, zone growth, Prometheus exporter), `abhed-bench` (measure, report) |
| Deployment, tests | Bash | `deploy/` | `build.sh`, `lab.sh`, `test.sh`, `bench.sh`, pinned versions |
| Container | | `Containerfile` | Podman / Buildah image of the whole stack |
| Cross-check | Python | `reference/` | Earlier prototype, kept only as an independent implementation |

```
            trust anchor
                 │
 dig ──► Unbound + ABHED patch ──┬─► NSD + ABHED patch  "."         127.0.53.10
          127.0.53.53            ├─► NSD + ABHED patch  "lab."      127.0.53.20
                                 └─► NSD + ABHED patch  "iem.lab."  127.0.53.30
 abhed-signzone ─► signed zone files          abhedctl / abhed-bench read NSD and Unbound statistics
```

## Quick start

**New to Linux, or on Windows / macOS?** Follow the step-by-step guide
[`docs/SETUP.md`](docs/SETUP.md). It starts from a computer with nothing installed
(Windows through WSL2, macOS through a Multipass virtual machine) and explains every output.

On Ubuntu 24.04:

```bash
sudo apt-get update
sudo apt-get install -y git ca-certificates build-essential cmake ninja-build autoconf automake \
    libtool flex bison pkg-config libssl-dev libevent-dev libexpat1-dev libldns-dev golang-go dnsutils
git clone https://github.com/drajdeep/ABHED-v2-native.git && cd ABHED-v2-native
sudo bash deploy/build.sh               # liboqs, libabhed, tools, patched NSD + Unbound -> /opt/abhed
sudo bash deploy/test.sh                # 60 end-to-end checks on the real engines: "60 passed, 0 failed"
```

Then, in a root shell (`sudo -s`):

```bash
export PATH=/opt/abhed/bin:/opt/abhed/sbin:$PATH
abhedctl init --dir /tmp/abhed-lab --mode mtl --hosts 1000 --profile abhed
bash deploy/lab.sh up /tmp/abhed-lab
dig @127.0.53.53 +dnssec host000042.iem.lab A        # "ad" flag: validated by Unbound
dig @127.0.53.53 +dnssec nosuchname.iem.lab A        # validated NXDOMAIN
dig @127.0.53.53 +dnssec host000044.iem.lab A | abhed-sigdump   # what kind of MTL signature arrived
abhedctl status --dir /tmp/abhed-lab                 # server counters
bash deploy/lab.sh down /tmp/abhed-lab
```

Benchmarks: `sudo bash deploy/bench.sh` (see [`docs/SETUP.md`](docs/SETUP.md#8-run-the-benchmarks)).

## Using the patched engines yourself

Resolver (`unbound.conf`):

```
server:
    trust-anchor-file: "/etc/unbound/trust-anchor.ds"
    abhed-sigtag: yes                  # send the SigTag option (default yes)
    abhed-compact: no                  # also ask for trimmed, compact signatures (default no)
    abhed-ladder-cache-zones: 100000
```

Zone signing:

```bash
abhed-keygen ...                                    # see docs/USAGE.md
abhed-signzone -o example. -f example.signed -k Kexample -s state/ example.zone
```

NSD needs no configuration: it recognises MTL RRSIGs when it loads the zone.

## Documentation

| Document | Content |
|---|---|
| [`docs/SETUP.md`](docs/SETUP.md) | **Start here.** From an empty computer to a running lab: Windows, macOS, Linux; troubleshooting |
| [`docs/USAGE.md`](docs/USAGE.md) | Every tool and option |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Wire formats, what each patch changes, fail-safe behaviour |
| [`docs/UDP_FIT.md`](docs/UDP_FIT.md) | Why answers do or do not fit in UDP; the ABHED profile; rejected ideas |
| [`docs/IETF_ALIGNMENT.md`](docs/IETF_ALIGNMENT.md) | Drafts, mailing-list concerns, open points, interoperability |
| [`docs/TESTING.md`](docs/TESTING.md) | What is tested and how to check by hand |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | What this does not show |
| [`results/REPORT.md`](results/REPORT.md) | Results of the reference run |

## Acknowledgements

Supported by the **IEM-UEM Group**, the **India Internet Foundation (IIFON)**, and **AIORI** under
the **Ministry of Electronics and Information Technology (MeitY), Government of India**.

NSD, Unbound and ldns are by NLnet Labs. Merkle Tree Ladder mode and the SigTag extension are
the work of Verisign Labs. ML-DSA for DNSSEC is specified by B. Westerbaan and S. Schmieg.
ML-DSA-44 comes from liboqs (Open Quantum Safe).

## Citation

```bibtex
@software{das2026abhedv2,
  author  = {Das, Rajdeep},
  title   = {{ABHED-v2}: {ML-DSA-44} and {ML-DSA-44-MTL} {DNSSEC} on {NSD} and {Unbound}},
  year    = {2026},
  version = {2.1.1},
  note    = {IEM-UEM, Kolkata, India},
  url     = {https://github.com/drajdeep/ABHED-v2-native}
}
```

## License and ownership

Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India.

ABHED is open source under the [Apache License, Version 2.0](LICENSE). Anyone may use, study,
change and share it, including commercially, provided that:

- every copy and derivative keeps [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), the copyright
  headers and the creator's name, and states which files were changed;
- modified versions are **not** distributed under the name "ABHED" or presented as official or
  endorsed ([`TRADEMARKS.md`](TRADEMARKS.md)).

The project is maintained by its creator ([`GOVERNANCE.md`](GOVERNANCE.md)). Contributions are
accepted under a [Contributor Licence Agreement](CLA.md), so the copyright holder keeps the right
to relicense the project. NSD, Unbound, liboqs and ldns keep their own licences. The MTL drafts
carry IPR statements from Verisign; read them before any use beyond research.

## Contributing, security, contact

- How to contribute: [`CONTRIBUTING.md`](CONTRIBUTING.md) · Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Security flaws: report privately, see [`SECURITY.md`](SECURITY.md)
- Contact: Rajdeep Das · Rajdeep.Das2025@iem.edu.in

# Limitations

## Maturity

- **Experimental patches.** The engines are production software; the patches are not. They
  have had no security audit, no fuzzing campaign and no review by NLnet Labs.
- **Verified by tests, not line by line.** The NSD patch in particular was validated through
  the end-to-end tests and counters rather than an independent code review.
- **Pinned versions.** The patches apply to NSD 4.15.4 and Unbound 1.26.2 only.
- **OpenSSL build of Unbound only.** The NSS and Nettle code paths are not patched.
- **Tested platform: Ubuntu 24.04, x86-64, native.** A clean build with Go 1.22.2 (the Ubuntu
  24.04 version) and the full test suite pass there. WSL2, Multipass on macOS, ARM CPUs and
  other distributions are documented in `docs/SETUP.md` but were not tested.
- **The Containerfile was not executed** (no registry access in the build environment), and the
  GitHub Actions workflow had not completed a run at the time of release.

## Protocol

- **Internet-Drafts.** Formats may change. The two MTL drafts were read as summaries.
- **Lab code points.** Algorithm 244 and EDNS options 65001 / 65002 are local choices,
  compiled in.
- **Compact type 0xF1, path trimming and the ABHED option are this project's proposals**, with
  no outside review.
- **No interoperability test with Verisign's NSD / Unbound forks.** Their reference library
  uses plain SHAKE in place of cSHAKE, so hashes are expected to differ
  (see `docs/IETF_ALIGNMENT.md`).
- **Downstream clients.** Unbound caches and returns RRSIGs in the form it received them. A
  validating stub behind the resolver may get a condensed or compact signature it cannot
  verify. Clients that rely on the resolver's `ad` flag are not affected.
- **Ladder cache is keyed by zone name.** It is not flushed on key rollover.
- **SigTags can be used to track a resolver**, as the SigTag draft notes.

## Experiment

- **One machine, loopback network.** No latency, loss, MTU limits, middleboxes or anycast.
  Reported resolver times are therefore not meaningful as latency; byte and query counts are.
- **Zones up to 100,000 names.** Larger sizes are calculated.
- **Synthetic workload** (Zipf popularity; 80% A, 10% NXDOMAIN, 5% NODATA, 5% other).
- **NSEC only.** No NSEC3, wildcards or CNAME chains in the test zones.
- **No key rollover, IXFR, online signing or multi-signer scenarios.** Churn is modelled as
  re-sign and reload.
- **Private keys are plain files.** No HSM or PKCS#11.
- **ML-DSA-44 only.** No ML-DSA-65/87, SLH-DSA-MTL or FN-DSA.
- **`split` is not post-quantum for zone data.**

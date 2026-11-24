# Changelog

## 2.1.1 (2026-11-24): setup and packaging

- `docs/SETUP.md`: step-by-step setup from a machine with nothing installed (Linux, Windows
  with WSL2, macOS with a virtual machine).
- Scripts no longer depend on the executable bit (`sudo bash deploy/...`), so a ZIP download or
  an upload from Windows works. Clear messages when not run as root or before building.
- `build.sh` checks the Go version and downloads Go dependencies if `go/vendor/` is missing.
- `go.mod` no longer forces a Go 1.24 toolchain download; Go 1.22 (Ubuntu 24.04) builds it.
- CI and Containerfile fixed for the same reasons; `.gitattributes` keeps LF line endings.
- Governance: `CLA.md`, `GOVERNANCE.md`, `TRADEMARKS.md`, `CODEOWNERS`, issue and pull
  request templates. Licence stays Apache-2.0.

## 2.1.0 (2026-11-12): native engines

- The stack is now C, Go and Bash. No Python in the product.
- `libabhed` (C): cSHAKE128, MTL node set, ladder, full / condensed / compact signatures,
  SigTag, thread-safe ladder cache, ML-DSA-44 through liboqs.
- `abhed-signzone`, `abhed-keygen`, `abhed-sigdump` (C, on ldns).
- Patch for Unbound 1.26.2: validates algorithms 18 and ML-DSA-44-MTL, caches ladders, sends
  the SigTag option upstream. New options `abhed-sigtag`, `abhed-compact`,
  `abhed-ladder-cache-zones`.
- Patch for NSD 4.15.4: stores MTL signatures condensed, composes full / condensed / compact
  per query from the SigTag option, new statistics counters.
- `abhedctl`, `abhed-bench` (Go): lab setup, zone growth, Prometheus exporter, benchmarks, report.
- `deploy/build.sh`, `lab.sh`, `test.sh`, `bench.sh`; `Containerfile` for Podman.
- The Python prototype moved to `reference/`.

## 2.0.0 (2026-11-12): Python prototype on the current drafts
## 1.0.0 (2026-10-12): first release

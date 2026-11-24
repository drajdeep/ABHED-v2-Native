# Contributing

Bug reports, measurements from other machines, reviews and patches are welcome.
Read [GOVERNANCE.md](GOVERNANCE.md) first: the project has one maintainer, who decides what is merged.

## Before you start

1. Open an issue for anything larger than a small fix, so the approach can be agreed first.
2. Set the project up as described in [docs/SETUP.md](docs/SETUP.md).

## Making a change

1. Fork the repository and create a branch. Keep each pull request to one topic.
2. Build and test:
   ```bash
   sudo bash deploy/build.sh        # also runs the libabhed unit tests
   sudo bash deploy/test.sh         # must end with "0 failed"
   ```
3. Add a test for every behaviour you change.
4. If you change a wire format or a code point, update `docs/DESIGN.md` and
   `docs/IETF_ALIGNMENT.md` and name the draft version you followed.
5. Keep the copyright header in existing files. Apache-2.0 section 4 requires a notice in each
   file you change; add a line such as `Modified 2026 by <your name>` under the header.
6. Never commit a lab directory or anything from `keys/`: they contain private keys.
7. Open the pull request and tick the CLA box in the template.

## Contributor Licence Agreement

Every contribution is accepted under [CLA.md](CLA.md). In short: you keep your copyright, and you
allow the maintainer to distribute your contribution under Apache-2.0 or other terms. Pull
requests without CLA agreement are not merged.

## Especially useful

- interoperability tests against Verisign's `mtl-mode-nsd` / `mtl-mode-unbound` forks;
- review of the Unbound and NSD patches by people who know those code bases;
- NSEC3, key rollover and IXFR scenarios;
- results from real networks (loss, MTU limits, middleboxes) and from ARM machines.

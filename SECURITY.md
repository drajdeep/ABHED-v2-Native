# Security policy

ABHED-v2 is a research testbed. **Do not use it to sign or serve real zones.**

- The Unbound and NSD patches are new code inside mature engines. They are written carefully
  but have had no security audit and no upstream review.
- Lab private keys are stored unencrypted in each lab directory under `keys/`.
- The compact signature type (0xF1) and the ABHED EDNS option are this project's own proposals.
  They have no security proof and no IETF review.

## Reporting a vulnerability

If you find a flaw in the cryptographic handling (for example a way to make the validator
accept a forged RRset, or to crash NSD or Unbound with a crafted packet), email
**Rajdeep.Das2025@iem.edu.in** with the subject "ABHED security" **before** opening a public
issue. You can also use GitHub's private vulnerability reporting on the repository's
Security tab. You should get an answer within 7 days.

Other bugs can go straight to the issue tracker.

## Supported versions

Only the latest release on `main` receives fixes.

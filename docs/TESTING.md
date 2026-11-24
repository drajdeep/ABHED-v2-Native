# Testing

## 1. Library unit tests

Run by `deploy/build.sh` (and `ctest` in the libabhed build directory): 1,709 checks, including
cSHAKE128 vectors, the rung layout of the draft's N = 14 figure, signature sizes, round trips,
tampering, backward compatibility, and malformed input. `deploy/build.sh --sanitize` runs them
under AddressSanitizer and UBSan.

`lib/libabhed/tests/vectors.txt` holds hash vectors. The C library and the Python prototype in
`reference/` were also checked against each other in both directions (leaf hashes, and a full
signature made by one verified by the other).

## 2. End-to-end tests on the engines

```bash
sudo bash deploy/test.sh          # expect: 60 passed, 0 failed
```

For each of `mtl/abhed`, `mtl/sigtag`, `mtl/base`, `mldsa44`, `split`, `ecdsa` it signs the
three zones, starts three patched NSD and one patched Unbound, and checks through Unbound with
`dig`:

| Check | Expectation |
|---|---|
| two positive answers, NXDOMAIN, NODATA, apex MX, a name in the parent zone | right rcode and the `ad` flag |
| MTL profiles | NSD counters show only full signatures (`base`), condensed (`sigtag`), compact (`abhed`) |
| zone grown by 5 hosts and re-signed in the same series | an old name and a new name both validate |
| one A record altered in the served zone file | that name gives SERVFAIL, its neighbour still validates |

## 3. Checks by hand

```bash
abhedctl init --dir /tmp/lab --mode mtl --hosts 1000 --profile abhed && bash deploy/lab.sh up /tmp/lab
dig @127.0.53.53 +dnssec host000042.iem.lab A                 # ad flag
dig @127.0.53.30 +dnssec +norec +notcp +ignore host000042.iem.lab A   # tc flag, empty
dig @127.0.53.30 +dnssec +norec +tcp host000042.iem.lab A     # full signature, about 3 kB
dig @127.0.53.30 +dnssec +norec +notcp +ignore iem.lab DNSKEY # tc: the key is 1,312 bytes
abhedctl status --dir /tmp/lab                                # full / condensed / compact counters
unbound-control -c /tmp/lab/etc/unbound.conf stats_noreset | grep -E "secure|bogus"
```

## 4. Benchmarks

`deploy/bench.sh` regenerates `results/`. Sizes and query counts are deterministic for a given
seed; times depend on the machine. The shipped run took about one minute on a 2-core machine.

# Usage

Install first: [`SETUP.md`](SETUP.md). Then add the tools to the path: `export PATH=/opt/abhed/bin:/opt/abhed/sbin:$PATH`.
Every tool prints its options when run without arguments.

## Lab control: `abhedctl` (Go)

```
abhedctl init    --dir DIR [--mode mtl|mldsa44|split|ecdsa] [--layout csk|split]
                 [--order hot-last|canonical] [--hosts N] [--profile abhed|sigtag|base]
                 [--tcp-upstream] [--tuned=true] [--prefix /opt/abhed] [--port 53]
abhedctl render  --dir DIR [--profile P] [--tcp-upstream=B] [--tuned=B]    rewrite configs only
abhedctl grow    --dir DIR --add N       add hosts to iem.lab., re-sign in the same series, reload NSD
abhedctl resign  --dir DIR               re-sign all zones with the same keys and series
abhedctl status  --dir DIR               lab description and server counters
abhedctl metrics --dir DIR [--listen 127.0.0.1:9153]    Prometheus exporter
abhedctl env     --dir DIR               shell variables for deploy/lab.sh
```

| Mode | Keys |
|---|---|
| `ecdsa` | ECDSA P-256 KSK + ZSK |
| `mldsa44` | ML-DSA-44 KSK + ZSK |
| `split` | ML-DSA-44 KSK + ECDSA ZSK |
| `mtl`, `--layout csk` | one ML-DSA-44-MTL key signs everything |
| `mtl`, `--layout split` | ML-DSA-44 KSK + ML-DSA-44-MTL ZSK |

| Profile | Unbound sends | NSD answers with |
|---|---|---|
| `base` | nothing | full signatures (MTL-Type 0x01) |
| `sigtag` | SigTag option | condensed signatures (0x02) when a tag matches |
| `abhed` | SigTag + ABHED option | trimmed, compact signatures (0xF1) |

`init` creates `DIR/zones` (unsigned and signed zone files, DS sets), `DIR/keys`, `DIR/state`
(MTL series state), `DIR/etc` (NSD and Unbound configuration, root hints, trust anchor).

## Running the lab: `deploy/lab.sh` (Bash)

```
sudo bash deploy/lab.sh up | down | restart | restart-resolver | reload | status | logs   DIR
```

Three NSD instances and one Unbound, as ordinary processes. `restart-resolver` gives a cold
resolver (empty caches, empty ladder cache). `reload` makes NSD re-read its zones.

## Zone tools (C)

```
abhed-keygen                 create a key pair (run it for the options)
abhed-signzone -o origin -f signed.zone -k keyprefix [-k keyprefix ...]
               [-s statedir] [-e days] [-r days] [-l hot-last|canonical] [-t unixtime] [-N] [-q] unsigned.zone
abhed-sigdump                decode RRSIG signature fields (run it for the options)
```

- A key with flags 257 signs the DNSKEY RRset; a key with flags 256 signs the rest. With only
  a 257 key it signs everything.
- `-s` holds the MTL series (node set and leaf map). Signing again continues the series:
  unchanged RRsets keep their leaf, and one new ML-DSA-44 signature covers the new ladder.
- `-N` starts a new series with a new SID. `-r` re-leafs signatures close to expiry.

## Benchmarks: `abhed-bench` (Go) and `deploy/bench.sh`

```
abhed-bench workload --dir DIR --config NAME [--label TEXT] [--trials 5] [--queries 500] [--out results]
abhed-bench sizes    --dir DIR --config NAME [--label TEXT] [--samples 200] [--out results]
abhed-bench churn    --dir DIR --config NAME [--label TEXT] [--steps 20] [--alpha 10] [--rho 50] [--out results]
abhed-bench report   [--out results] [--order cfg1,cfg2,...]
```

The lab must be running. `deploy/bench.sh` runs all eight configurations and the report:

```
sudo bash deploy/bench.sh [--hosts 10000] [--trials 5] [--queries 500] [--churn-hosts 1000] [--out results]
```

## Unbound options added by the patch

| Option | Default | Meaning |
|---|---|---|
| `abhed-sigtag:` | yes | send the SigTag EDNS option with the ladders held for the queried zone |
| `abhed-compact:` | no | also send the ABHED option (accept trimmed paths and MTL-Type 0xF1) |
| `abhed-ladder-cache-zones:` | 100000 | size of the ladder cache, in zones |

## NSD statistics added by the patch

`nsd-control stats` gains `abhed.mtl.full`, `abhed.mtl.condensed`, `abhed.mtl.compact`,
`abhed.mtl.dedup`, `abhed.mtl.trimmed`, `abhed.tcp.queries`, `abhed.bytes.udp`,
`abhed.bytes.tcp`. `abhedctl metrics` exports them for Prometheus.

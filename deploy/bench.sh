#!/usr/bin/env bash
# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
#
# Run every benchmark against the real engines and build results/REPORT.md.
#
# usage: deploy/bench.sh [--prefix /opt/abhed] [--dir /tmp/abhed-bench] [--out results]
#                        [--hosts 10000] [--trials 5] [--queries 500] [--churn-hosts 1000]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=/opt/abhed; DIR=/tmp/abhed-bench; OUT=results; HOSTS=10000; TRIALS=5; QUERIES=500; CHOSTS=1000
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=$2; shift 2 ;; --dir) DIR=$2; shift 2 ;; --out) OUT=$2; shift 2 ;;
    --hosts) HOSTS=$2; shift 2 ;; --trials) TRIALS=$2; shift 2 ;; --queries) QUERIES=$2; shift 2 ;;
    --churn-hosts) CHOSTS=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root: sudo bash deploy/bench.sh (the lab binds port 53)" >&2; exit 1; }
export PATH="$PREFIX/bin:$PREFIX/sbin:$PATH"
mkdir -p "$OUT"

# name | abhedctl init options | label
CONFIGS=(
  "ecdsa|--mode ecdsa --profile base|ECDSA P-256 (classical reference)"
  "split|--mode split --profile base|ML-DSA-44 KSK + ECDSA ZSK"
  "mldsa44|--mode mldsa44 --profile base|ML-DSA-44, UDP then TCP"
  "mldsa44-tcp|--mode mldsa44 --profile base --tcp-upstream|ML-DSA-44, TCP only"
  "mtl-base|--mode mtl --layout split --order canonical --profile base|MTL base draft, UDP then TCP"
  "mtl-base-tcp|--mode mtl --layout split --order canonical --profile base --tcp-upstream|MTL base draft, TCP only"
  "mtl-sigtag|--mode mtl --layout split --order canonical --profile sigtag|MTL + SigTag extension"
  "mtl-abhed|--mode mtl --layout csk --order hot-last --profile abhed|MTL + SigTag + ABHED profile"
)
CHURN="mldsa44-tcp mtl-base-tcp mtl-sigtag mtl-abhed"
ORDER=""
for c in "${CONFIGS[@]}"; do
  IFS='|' read -r name opts label <<<"$c"
  ORDER="${ORDER:+$ORDER,}$name"
  echo "== $name: sizes + workload ($HOSTS hosts)"
  bash "$HERE/lab.sh" down "$DIR" >/dev/null 2>&1 || true; rm -rf "$DIR"
  # shellcheck disable=SC2086
  abhedctl init --dir "$DIR" --hosts "$HOSTS" $opts >/dev/null
  bash "$HERE/lab.sh" up "$DIR" >/dev/null
  abhed-bench sizes    --dir "$DIR" --config "$name" --label "$label" --out "$OUT"
  abhed-bench workload --dir "$DIR" --config "$name" --label "$label" --trials "$TRIALS" --queries "$QUERIES" --out "$OUT" --lab-sh "$HERE/lab.sh"
  bash "$HERE/lab.sh" down "$DIR" >/dev/null 2>&1 || true
  if [[ " $CHURN " == *" $name "* ]]; then
    echo "== $name: churn ($CHOSTS hosts)"
    rm -rf "$DIR"
    # shellcheck disable=SC2086
    abhedctl init --dir "$DIR" --hosts "$CHOSTS" $opts >/dev/null
    bash "$HERE/lab.sh" up "$DIR" >/dev/null
    abhed-bench churn --dir "$DIR" --config "$name" --label "$label" --out "$OUT" --lab-sh "$HERE/lab.sh"
    bash "$HERE/lab.sh" down "$DIR" >/dev/null 2>&1 || true
  fi
done
abhed-bench report --out "$OUT" --order "$ORDER"

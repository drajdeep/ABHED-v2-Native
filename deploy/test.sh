#!/usr/bin/env bash
# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end tests against the real engines (patched NSD + patched Unbound).
# For every algorithm mode and resolver profile: sign, start, resolve through Unbound and
# require a validated answer (AD flag); then grow the zone, then tamper with it.
#
# usage: deploy/test.sh [--prefix /opt/abhed] [--dir /tmp/abhed-test] [--hosts 200]
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=/opt/abhed; DIR=/tmp/abhed-test; HOSTS=200
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=$2; shift 2 ;; --dir) DIR=$2; shift 2 ;; --hosts) HOSTS=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root: sudo bash deploy/test.sh (the lab binds port 53)" >&2; exit 1; }
[ -x "$PREFIX/sbin/unbound" ] || { echo "nothing built in $PREFIX: run sudo bash deploy/build.sh first" >&2; exit 1; }
export PATH="$PREFIX/bin:$PREFIX/sbin:$PATH"
RES=127.0.53.53
pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }

# expect NAME TYPE RCODE ad|noad
expect() {
  local out status flags
  out=$(dig @"$RES" +dnssec +tries=2 +time=5 "$1" "$2" 2>&1)
  status=$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$out" | head -1)
  flags=$(sed -n 's/^;; flags: \([a-z ]*\);.*/\1/p' <<<"$out" | head -1)
  if [ "$status" = "$3" ] && { { [ "$4" = ad ] && [[ " $flags " == *" ad "* ]]; } ||
                               { [ "$4" = noad ] && [[ " $flags " != *" ad "* ]]; }; }; then
    ok "$1 $2 -> $3 ${4}"
  else
    bad "$1 $2: wanted $3 $4, got status=$status flags=[$flags]"
  fi
}
counter() { abhedctl status --dir "$DIR" | grep -o "nsd_iem .*" | grep -o "$1=[0-9]*" | cut -d= -f2; }

run() {   # run MODE PROFILE
  local mode=$1 profile=$2
  printf '\n== mode=%s profile=%s\n' "$mode" "$profile"
  bash "$HERE/lab.sh" down "$DIR" >/dev/null 2>&1; rm -rf "$DIR"
  abhedctl init --dir "$DIR" --mode "$mode" --hosts "$HOSTS" --profile "$profile" >/dev/null || { bad "init"; return; }
  bash "$HERE/lab.sh" up "$DIR" >/dev/null || { bad "lab up"; bash "$HERE/lab.sh" logs "$DIR" | tail -5; return; }
  expect host000042.iem.lab A NOERROR ad
  expect host000007.iem.lab A NOERROR ad
  expect host000042x.iem.lab A NXDOMAIN ad
  expect www.iem.lab AAAA NOERROR ad
  expect iem.lab MX NOERROR ad
  expect www.lab A NOERROR ad
  if [ "$mode" = mtl ]; then
    local full cond comp
    full=$(counter abhed.mtl.full); cond=$(counter abhed.mtl.condensed); comp=$(counter abhed.mtl.compact)
    case "$profile" in
      base)   [ "$cond" = 0 ] && [ "$comp" = 0 ] && [ "$full" -gt 0 ] && ok "base: only full signatures ($full)" || bad "base: full=$full condensed=$cond compact=$comp" ;;
      sigtag) [ "$cond" -gt 0 ] && [ "$comp" = 0 ] && ok "sigtag: condensed signatures served ($cond)" || bad "sigtag: full=$full condensed=$cond compact=$comp" ;;
      abhed)  [ "$comp" -gt 0 ] && ok "abhed: compact signatures served ($comp)" || bad "abhed: full=$full condensed=$cond compact=$comp" ;;
    esac
    abhedctl grow --dir "$DIR" --add 5 >/dev/null && ok "grow: zone re-signed in the same series" || bad "grow"
    sleep 1
    expect host000011.iem.lab A NOERROR ad            # old record, resolver holds the old ladder
    expect "$(printf 'host%06d.iem.lab' $((HOSTS+3)))" A NOERROR ad   # new record
  fi
  # tampering: change one address in the served zone; the resolver must refuse it
  sed -i -E 's/^(host000050\.iem\.lab\.[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+A[[:space:]]+).*/\1 10.99.99.99/' "$DIR/zones/iem.lab.signed"
  bash "$HERE/lab.sh" reload "$DIR" >/dev/null; sleep 1
  expect host000050.iem.lab A SERVFAIL noad
  expect host000051.iem.lab A NOERROR ad
  bash "$HERE/lab.sh" down "$DIR" >/dev/null 2>&1
}

run mtl abhed
run mtl sigtag
run mtl base
run mldsa44 base
run split base
run ecdsa base
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]

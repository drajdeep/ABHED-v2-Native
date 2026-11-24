#!/usr/bin/env bash
# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
#
# Run an ABHED lab natively (Linux; uses 127.0.53.0/24 on the loopback interface).
#
#   deploy/lab.sh up               DIR   start 3 NSD instances + Unbound
#   deploy/lab.sh down             DIR   stop everything
#   deploy/lab.sh restart          DIR
#   deploy/lab.sh restart-resolver DIR   cold resolver (empty caches, empty ladder cache)
#   deploy/lab.sh reload           DIR   NSD reloads its zones
#   deploy/lab.sh status           DIR
#   deploy/lab.sh logs             DIR
#
# Prepare DIR first with:  abhedctl init --dir DIR ...
set -euo pipefail
CMD=${1:-help}
DIR=${2:-lab}
log() { printf '\033[32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mxx\033[0m %s\n' "$*" >&2; exit 1; }

if [ "$CMD" = help ] || [ "$CMD" = -h ]; then sed -n '4,14p' "$0"; exit 0; fi
ABHEDCTL=${ABHEDCTL:-$(command -v abhedctl || echo /opt/abhed/bin/abhedctl)}
[ -f "$DIR/lab.json" ] || die "$DIR is not a lab (run: abhedctl init --dir $DIR)"
eval "$("$ABHEDCTL" env --dir "$DIR")"
RUN=$ABHED_DIR/run
mkdir -p "$RUN"

alive() { local p; p=$(cat "$1" 2>/dev/null) && [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }

wait_dns() {   # wait_dns ADDR NAME
  for _ in $(seq 1 50); do
    if dig +time=1 +tries=1 -p "$PORT" @"$1" "$2" SOA +norec >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  return 1
}

start_nsd() {
  local n=$1 addr_var="ADDR_${1^^}"
  if alive "$RUN/nsd-$n.pid"; then return; fi
  "$NSD" -c "$ABHED_DIR/etc/nsd-$n.conf" || die "nsd $n failed: see $RUN/nsd-$n.log"
}

stop_pid() {
  local pidf=$1
  local p
  p=$(cat "$pidf" 2>/dev/null) || p=""
  if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
    kill "$p"
    for _ in $(seq 1 50); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$p" 2>/dev/null || true
  fi
  rm -f "$pidf"
}

start_unbound() {
  if alive "$RUN/unbound.pid"; then return; fi
  rm -f "$RUN/unbound.pid"
  "$UNBOUND" -c "$ABHED_DIR/etc/unbound.conf" || die "unbound failed: see $RUN/unbound.log"
  for _ in $(seq 1 50); do
    "$UNBOUND_CONTROL" -c "$ABHED_DIR/etc/unbound.conf" status >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  die "unbound did not come up: see $RUN/unbound.log"
}

case "$CMD" in
  up)
    for n in $SERVERS; do start_nsd "$n"; done
    wait_dns "$ADDR_ROOT" . || die "root server not answering"
    wait_dns "$ADDR_LAB" lab. || die "lab. server not answering"
    wait_dns "$ADDR_IEM" iem.lab. || die "iem.lab. server not answering"
    start_unbound
    log "lab up: resolver $RESOLVER_ADDR:$PORT, authoritative $ADDR_ROOT $ADDR_LAB $ADDR_IEM"
    ;;
  down)
    stop_pid "$RUN/unbound.pid"
    for n in $SERVERS; do stop_pid "$RUN/nsd-$n.pid"; done
    log "lab down"
    ;;
  restart) bash "$0" down "$DIR"; bash "$0" up "$DIR" ;;
  restart-resolver)
    stop_pid "$RUN/unbound.pid"
    start_unbound
    ;;
  reload)
    for n in $SERVERS; do "$NSD_CONTROL" -c "$ABHED_DIR/etc/nsd-$n.conf" reload >/dev/null; done
    "$UNBOUND_CONTROL" -c "$ABHED_DIR/etc/unbound.conf" flush_zone . >/dev/null || true
    log "zones reloaded, resolver cache flushed"
    ;;
  status)
    for n in $SERVERS; do
      printf '%-8s ' "nsd-$n"; alive "$RUN/nsd-$n.pid" && echo "running (pid $(cat "$RUN/nsd-$n.pid"))" || echo stopped
    done
    printf '%-8s ' unbound; alive "$RUN/unbound.pid" && echo "running (pid $(cat "$RUN/unbound.pid"))" || echo stopped
    "$ABHEDCTL" status --dir "$DIR"
    ;;
  logs) tail -n 30 "$RUN"/*.log ;;
  *) die "unknown command $CMD (see: $0 help)" ;;
esac

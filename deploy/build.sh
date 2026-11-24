#!/usr/bin/env bash
# Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
# SPDX-License-Identifier: Apache-2.0
#
# Build the ABHED stack from source into one prefix:
#   liboqs (ML-DSA-44 only) -> libabhed -> abhed tools -> patched NSD -> patched Unbound
#
# usage: deploy/build.sh [--prefix /opt/abhed] [--jobs N] [--sanitize] [--clean]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
# shellcheck source=deploy/versions.env
source "$HERE/versions.env"

PREFIX=/opt/abhed
JOBS=$(nproc 2>/dev/null || echo 2)
SANITIZE=OFF
CLEAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=$2; shift 2 ;;
    --jobs) JOBS=$2; shift 2 ;;
    --sanitize) SANITIZE=ON; shift ;;
    --clean) CLEAN=1; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
SRC=${ABHED_SRC:-$ROOT/.build}
[ "$CLEAN" = 1 ] && rm -rf "$SRC"
log() { printf '\033[32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mxx\033[0m %s\n' "$*" >&2; exit 1; }
if [ "$(id -u)" != 0 ] && ! { mkdir -p "$PREFIX" 2>/dev/null && [ -w "$PREFIX" ]; }; then
  die "run as root (sudo bash deploy/build.sh), or pass --prefix to a directory you own"
fi
mkdir -p "$SRC" "$PREFIX"

need() { command -v "$1" >/dev/null || die "missing tool: $1 (see docs/SETUP.md, section 2)"; }
for t in git cmake ninja gcc make autoconf automake libtoolize flex bison pkg-config; do need "$t"; done
pkg-config --exists ldns || die "missing libldns development files (libldns-dev / ldns-devel)"
pkg-config --exists libevent || die "missing libevent development files"
pkg-config --exists openssl || die "missing OpenSSL development files"

fetch() {  # fetch <dir> <repo> <ref>
  if [ ! -d "$SRC/$1/.git" ]; then
    log "fetching $2 @ $3"
    git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$3" "$2" "$SRC/$1"
  else
    git -C "$SRC/$1" fetch --quiet --depth 1 origin "refs/tags/$3:refs/tags/$3" 2>/dev/null || true
    git -C "$SRC/$1" checkout --quiet --force "$3"
    git -C "$SRC/$1" clean -fdxq
  fi
}

# ---------------------------------------------------------------- liboqs
if [ ! -f "$PREFIX/lib/liboqs.so" ] || [ "$CLEAN" = 1 ]; then
  fetch liboqs "$LIBOQS_REPO" "$LIBOQS_REF"
  log "building liboqs $LIBOQS_REF (ML-DSA-44 only)"
  cmake -S "$SRC/liboqs" -B "$SRC/liboqs/build" -GNinja -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
    -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44" -DCMAKE_INSTALL_PREFIX="$PREFIX" >/dev/null
  ninja -C "$SRC/liboqs/build" -j "$JOBS" install >/dev/null
fi

# ---------------------------------------------------------------- libabhed + tools
log "building libabhed and tools"
cmake -S "$ROOT/tools" -B "$SRC/abhed" -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" -DABHED_SANITIZE="$SANITIZE" -DCMAKE_PREFIX_PATH="$PREFIX" \
  -DOQS_INCLUDE="$PREFIX/include" -DOQS_LIB="$PREFIX/lib/liboqs.so" >/dev/null
ninja -C "$SRC/abhed" -j "$JOBS" >/dev/null
log "libabhed unit tests"
"$SRC/abhed/libabhed/test_libabhed" "$ROOT/lib/libabhed/tests/vectors.txt"
ninja -C "$SRC/abhed" install >/dev/null
cmake --install "$SRC/abhed/libabhed" >/dev/null

COMMON_CPP="-DUSE_ABHED -I$PREFIX/include"
COMMON_LD="-L$PREFIX/lib -Wl,-rpath,$PREFIX/lib"
COMMON_LIBS="$PREFIX/lib/libabhed.a -loqs -lpthread"

# ---------------------------------------------------------------- NSD
fetch nsd "$NSD_REPO" "$NSD_REF"
git -C "$SRC/nsd" submodule update --init --depth 1 --quiet
log "patching NSD $NSD_REF"
git -C "$SRC/nsd" apply "$ROOT/patches/nsd/"*.patch
( cd "$SRC/nsd/simdzone" && autoreconf -fi >/dev/null 2>&1 )
( cd "$SRC/nsd" && autoreconf -fi >/dev/null 2>&1 \
  && ./configure -q --prefix="$PREFIX" --with-libevent --disable-dnstap \
     --with-configdir="$PREFIX/etc/nsd" \
     CPPFLAGS="$COMMON_CPP" LDFLAGS="$COMMON_LD" LIBS="$COMMON_LIBS" >/dev/null \
  && make -j "$JOBS" >/dev/null && make install >/dev/null )
log "NSD installed: $("$PREFIX/sbin/nsd" -v 2>&1 | head -1)"

# ---------------------------------------------------------------- Unbound
fetch unbound "$UNBOUND_REPO" "$UNBOUND_REF"
log "patching Unbound $UNBOUND_REF"
git -C "$SRC/unbound" apply "$ROOT/patches/unbound/"*.patch
( cd "$SRC/unbound" && ./configure -q --prefix="$PREFIX" --with-libevent --with-ssl \
     --disable-flto --with-conf-file="$PREFIX/etc/unbound/unbound.conf" \
     CPPFLAGS="$COMMON_CPP" LDFLAGS="$COMMON_LD" LIBS="$COMMON_LIBS" >/dev/null \
  && make -j "$JOBS" >/dev/null && make install >/dev/null )
log "Unbound installed: $("$PREFIX/sbin/unbound" -V 2>&1 | head -1)"

# ---------------------------------------------------------------- Go tools
if command -v go >/dev/null; then
  GOV=$(go env GOVERSION | sed 's/^go//')
  case "$GOV" in 1.1[0-9]*|1.2[01]*) die "Go $GOV is too old; Go 1.22 or newer is needed" ;; esac
  if [ -f "$ROOT/go/vendor/modules.txt" ]; then
    log "building Go tools (vendored dependencies, offline)"; GOMOD=vendor
  else
    log "building Go tools (go/vendor missing: downloading dependencies)"; GOMOD=mod
  fi
  ( cd "$ROOT/go" && CGO_ENABLED=0 GOTOOLCHAIN=local go build -mod=$GOMOD -trimpath -o "$PREFIX/bin/" ./cmd/... )
else
  echo "go not found: skipping abhedctl / abhed-bench (install Go >= 1.22)" >&2
fi
log "done. Add $PREFIX/bin and $PREFIX/sbin to PATH."

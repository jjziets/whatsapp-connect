#!/bin/sh
# TRACEWEAVER: file-role=encrypted-build-test-entrypoint; req=REQ-WC-002; trace=TRACE-WC-002; ver=VER-WC-002
set -eu

# Reproducible encrypted build/test entrypoint. No key travels through this script.
WC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$WC_ROOT/scripts/build-native.sh"
WC_NATIVE="$WC_ROOT/work/native/build"
mkdir -p "$WC_ROOT/work/go-build" "$WC_ROOT/work/go-modules" "$WC_ROOT/bin"
export GOCACHE="${GOCACHE:-$WC_ROOT/work/go-build}"
export GOMODCACHE="${GOMODCACHE:-$WC_ROOT/work/go-modules}"
export GOTOOLCHAIN=local
export CGO_ENABLED=1
export CGO_CFLAGS="-I$WC_NATIVE -DSQLITE_HAS_CODEC"
export CGO_LDFLAGS="-L$WC_NATIVE -framework Security -framework CoreFoundation -lz"
cd "$WC_ROOT/server"
WC_ACTION=${1:-build}
if [ "$#" -gt 0 ]; then shift; fi
case "$WC_ACTION" in
  build) exec "$WC_ROOT/scripts/build-server.sh" build -o "$WC_ROOT/bin/whatsapp-connect" "$@" ;;
  test) exec "$WC_ROOT/scripts/build-server.sh" test "$@" ;;
  keychain-test) go test -tags libsqlite3,keychain_integration ./internal/securestore -run '^TestNativeKeychainRoundTrip$' -count=1 -v ;;
  plain-engine-test)
    unset CGO_CFLAGS CGO_LDFLAGS
    go test ./internal/securestore -run '^TestPlainSQLiteBuildRefusesSecureOpen$' -count=1 -v ;;
  *) echo 'Usage: scripts/server.sh build|test|keychain-test|plain-engine-test' >&2; exit 2 ;;
esac

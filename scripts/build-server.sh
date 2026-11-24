#!/bin/sh
# C-007: all server artifacts require the exact SHA-bound SDK overlay.
set -eu
WC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
case "${GOFLAGS-}" in *-overlay*) echo 'Refusing externally supplied overlay' >&2; exit 2;; esac
for WC_ARG in "$@"; do case "$WC_ARG" in -overlay|-overlay=*|--overlay|--overlay=*) echo 'Refusing externally supplied overlay' >&2; exit 2;; esac; done
WC_OVERLAY=$(python3 "$WC_ROOT/scripts/prepare-whatsmeow-overlay.py")
export GOWORK="$WC_OVERLAY/go.work"
cd "$WC_ROOT/server"
WC_ACTION=${1:-build}
if [ "$#" -gt 0 ]; then shift; fi
case "$WC_ACTION" in
 build) go build -overlay "$WC_OVERLAY/overlay.json" -tags libsqlite3 "$@" .;;
 test) go test -overlay "$WC_OVERLAY/overlay.json" -tags libsqlite3 "$@" ./...;;
 sdk-test) go test -overlay "$WC_OVERLAY/test-overlay.json" "$@" go.mau.fi/whatsmeow go.mau.fi/whatsmeow/socket;;
 *) echo 'Usage: build-server.sh build|test|sdk-test [Go flags]' >&2;exit 2;;
esac

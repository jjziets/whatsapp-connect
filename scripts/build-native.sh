#!/bin/sh
# TRACEWEAVER: file-role=sqlcipher-native-build; req=REQ-WC-002; trace=TRACE-WC-002; ver=VER-WC-002
set -eu

# Build the pinned official SQLCipher library locally; no system installation.
WC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WC_NATIVE="$WC_ROOT/work/native"
WC_SOURCE="$WC_NATIVE/sqlcipher-4.20.0"
WC_BUILD="$WC_NATIVE/build"
WC_CHECKSUM=38705f51b61ac0636a5fd064f9a77fafabc7227b2aa2513f1b14c8bb1102affc
WC_ID="sqlcipher-4.20.0-commoncrypto-fts5-static-v1-$WC_CHECKSUM"

if [ "$(uname -s)" != Darwin ]; then
  echo 'This build currently requires macOS and its native Keychain.' >&2
  exit 1
fi
if [ -f "$WC_BUILD/libsqlite3.a" ] && [ -f "$WC_BUILD/verified-build-id" ] && [ "$(cat "$WC_BUILD/verified-build-id")" = "$WC_ID" ]; then
  exit 0
fi
mkdir -p "$WC_NATIVE" "$WC_BUILD"
if [ ! -f "$WC_NATIVE/source.tar.gz" ]; then
  curl --fail --location --output "$WC_NATIVE/source.tar.gz" https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v4.20.0.tar.gz
fi
printf '%s  %s\n' "$WC_CHECKSUM" "$WC_NATIVE/source.tar.gz" | shasum -a 256 -c -
if [ ! -d "$WC_SOURCE" ]; then
  tar -xzf "$WC_NATIVE/source.tar.gz" -C "$WC_NATIVE"
fi
cd "$WC_BUILD"
"$WC_SOURCE/configure" --prefix="$WC_NATIVE/prefix" --disable-shared --disable-tcl --fts5 --with-tempstore=yes \
  CFLAGS='-O2 -DSQLITE_HAS_CODEC -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown -DSQLCIPHER_CRYPTO_CC' \
  LDFLAGS='-framework Security -framework CoreFoundation'
make -j4 libsqlite3.a sqlite3
WC_ACTUAL=$(./sqlite3 :memory: 'PRAGMA cipher_version;')
case "$WC_ACTUAL" in
  '4.20.0 community') ;;
  *) echo 'Expected SQLCipher engine was not built; refusing plaintext fallback.' >&2; exit 1 ;;
esac
printf '%s\n' "$WC_ID" > verified-build-id

#!/bin/sh
set -eu
umask 077
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package_root="$repo_root/tools/tunnel-keychain-launcher"
build_root="$repo_root/work/tunnel-keychain-launcher"
mkdir -p "$build_root/cache" "$build_root/modules" "$repo_root/bin"
export CLANG_MODULE_CACHE_PATH="$build_root/modules"
/usr/bin/xcrun swift build --package-path "$package_root" --scratch-path "$build_root/build" \
    --cache-path "$build_root/cache" --disable-sandbox --disable-keychain --disable-netrc \
    -debug-info-format none -c release --product tunnel-keychain-launcher
product_dir=$(/usr/bin/xcrun swift build --package-path "$package_root" --scratch-path "$build_root/build" \
    --cache-path "$build_root/cache" --disable-sandbox --disable-keychain --disable-netrc \
    -debug-info-format none -c release --show-bin-path)
/usr/bin/install -m 700 "$product_dir/tunnel-keychain-launcher" "$repo_root/bin/tunnel-keychain-launcher"
printf '%s\n' 'Built bin/tunnel-keychain-launcher (ignored local artifact); not installed as a service.'

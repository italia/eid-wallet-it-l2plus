#!/bin/bash
# Rebuilds OpenSSL.xcframework (libcrypto only) for iOS devices and the simulator (arm64, x86_64).
# Usage: ./build.sh [version]
set -euo pipefail

VERSION="${1:-3.5.9}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
CONFIG="no-shared no-tests no-apps no-docs no-engine no-dso no-async no-ui-console"

cd "$WORK"
curl -sSLO "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"
curl -sSLO "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz.sha256"
echo "$(cut -d' ' -f1 "openssl-$VERSION.tar.gz.sha256")  openssl-$VERSION.tar.gz" | shasum -a 256 -c -

build() {
  local target=$1 minflag=$2
  mkdir "$target"
  tar xzf "openssl-$VERSION.tar.gz" -C "$target" --strip-components 1
  (cd "$target" && ./Configure "$target" $CONFIG "$minflag" && make -j"$(sysctl -n hw.ncpu)" build_libs)
  mkdir -p "headers-$target"
  cp -R "$target/include/openssl" "headers-$target/"
}

build ios64-xcrun -mios-version-min=15.0
build iossimulator-arm64-xcrun -mios-simulator-version-min=15.0
build iossimulator-x86_64-xcrun -mios-simulator-version-min=15.0
mkdir simulator
lipo -create iossimulator-arm64-xcrun/libcrypto.a iossimulator-x86_64-xcrun/libcrypto.a -output simulator/libcrypto.a

rm -rf "$HERE/OpenSSL.xcframework"
xcodebuild -create-xcframework \
  -library ios64-xcrun/libcrypto.a -headers headers-ios64-xcrun \
  -library simulator/libcrypto.a -headers headers-iossimulator-arm64-xcrun \
  -output "$HERE/OpenSSL.xcframework"
cp ios64-xcrun/LICENSE.txt "$HERE/LICENSE.txt"

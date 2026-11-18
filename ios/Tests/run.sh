#!/bin/bash
# Runs the SDK tests on macOS (no device or card needed).
#   Core: secure messaging (ICAO 9303-11 App. D), AES-CMAC (RFC 4493), MRZ, input validation, JSON.
#   Pace: PACE ECDH/DH Generic Mapping against the BSI worked example, including a replayed exchange.
#   Sod:  SOD checks with a throwaway PKI, IAS vendor detection, DER helpers.
# Requires Xcode and OpenSSL 3 from Homebrew (brew install openssl@3).
set -euo pipefail
cd "$(dirname "$0")"
SRC=../Sources/L2PlusSDK
CRYPTO=../Sources/L2PlusCrypto
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
P=$(brew --prefix openssl@3)
O="$P/bin/openssl"

CORE="$SRC/L2PlusModels.swift $SRC/L2PlusApdu.swift $SRC/L2PlusCipher.swift $SRC/L2PlusSecureMessaging.swift $SRC/L2PlusCardIO.swift"
for m in L2PlusCms L2PlusPaceGroup; do
  xcrun clang -c -fobjc-arc -I"$P/include" -I"$CRYPTO/include" -o "$OUT/$m.o" "$CRYPTO/$m.m"
done
build() {
  xcrun swiftc -import-objc-header "$CRYPTO/include/L2PlusCrypto.h" -I"$CRYPTO/include" -o "$OUT/$1" "${@:2}" \
      "$OUT/L2PlusCms.o" "$OUT/L2PlusPaceGroup.o" -L"$P/lib" -lcrypto
}

build core $CORE Core/main.swift
"$OUT/core"

build pace $CORE $SRC/L2PlusPace.swift Pace/main.swift
"$OUT/pace"

mkpki() {
  mkdir -p "$OUT/$1"; pushd "$OUT/$1" >/dev/null
  "$O" req -x509 -newkey rsa:2048 -nodes -keyout csca.key -out csca.pem -days 365 -subj "/C=IT/CN=$2" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  "$O" req -newkey rsa:2048 -nodes -keyout ds.key -out ds.csr -subj "/C=IT/CN=Test DS" 2>/dev/null
  printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n" > ext.cnf
  "$O" x509 -req -in ds.csr -CA csca.pem -CAkey csca.key -CAcreateserial -out ds.pem -days 300 -extfile ext.cnf 2>/dev/null
  "$O" x509 -in csca.pem -outform DER -out csca.der
  popd >/dev/null
}
mkpki good "Test CSCA"; mkpki other "Other CSCA"; mkpki rogue "Test CSCA"
python3 - "$OUT" <<'PY'
import hashlib, sys
out = sys.argv[1]
def tlv(t, v):
    n = len(v)
    l = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255]))
    return bytes([t]) + l + v
dg1, dg11 = bytes([0x61, 1, 1]), bytes([0x6B, 1, 2])
alg = tlv(0x30, tlv(0x06, bytes.fromhex('608648016503040201')))
entries = b''.join(tlv(0x30, tlv(0x02, bytes([n])) + tlv(0x04, hashlib.sha256(d).digest())) for n, d in [(1, dg1), (11, dg11)])
open(f'{out}/lds.der', 'wb').write(tlv(0x30, tlv(0x02, b'\x00') + alg + tlv(0x30, entries)))
open(f'{out}/dg1.bin', 'wb').write(dg1); open(f'{out}/dg11.bin', 'wb').write(dg11)
PY
for p in good rogue; do
  "$O" cms -sign -binary -nodetach -in "$OUT/lds.der" -signer "$OUT/$p/ds.pem" -inkey "$OUT/$p/ds.key" \
      -econtent_type 2.23.136.1.1.1 -outform DER -out "$OUT/$p/sod.cms" -md sha256
done
python3 -c "import sys;d=bytearray(open(sys.argv[1],'rb').read());d[-10]^=1;open(sys.argv[2],'wb').write(d)" "$OUT/good/sod.cms" "$OUT/tampered.cms"

build sod $CORE $SRC/L2PlusSodVerifier.swift $SRC/L2PlusIas.swift Sod/main.swift
"$OUT/sod" "$OUT"

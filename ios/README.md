# L2+ SDK for iOS

Reads from an Italian electronic identity card (CIE) the evidence required by the IT-Wallet
"Level 2 Plus" (L2+) PID issuance flow, in a single NFC session:

| Card application | Operation | Output |
|---|---|---|
| eMRTD | PACE with CAN or MRZ data, then read | `dg1`, `dg11`, `sod_mrtd` |
| IAS | read | `ias_pk`, `sod_ias` |
| IAS | Internal Authentication of the backend challenge | `challenge_signed` |

The result maps one-to-one to the `mrtd` and `ias` objects of the `mrtd_validation_jwt` payload
described in the [IT-Wallet technical specification](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuance-l2plus.html).

The SDK does not make network calls and does not store anything. Collecting the CAN or the MRZ data,
getting the challenge, building and signing the JWT and talking to the PID Provider are up to the app.

## Requirements

- iOS 15 or later, iPhone with NFC
- Xcode 15 or later
- An App ID with the *NFC Tag Reading* capability

## Installation

Swift Package Manager:

```swift
.package(url: "https://github.com/italia/eid-wallet-it-l2plus.git", from: "1.0.0")
```

then add `L2PlusSDK` to the target dependencies.

In the app target:

- add the *Near Field Communication Tag Reading* capability (`com.apple.developer.nfc.readersession.formats` = `TAG`);
- add `NFCReaderUsageDescription` to `Info.plist`;
- list these AIDs under `com.apple.developer.nfc.readersession.iso7816.select-identifiers`:
  `A0000002471001`, `A0000000308000000009816001`, `A00000000039`.

## Usage

```swift
import L2PlusSDK

let trust = L2PlusTrustConfig(mrtdTrustAnchors: cscaCertificates)   // DER certificates
let sdk = L2PlusSdk(trust: trust)

sdk.start(access: .can("123456"), challenge: challenge) { result in
    switch result {
    case .success(let evidence):
        let json = evidence.toJson()    // goes into the mrtd_validation_jwt payload
    case .failure(let error):
        print(error.code, error.action)
    }
}
```

With the MRZ data returned by the Ministry of the Interior service:

```swift
sdk.start(access: .mrz(documentNumber: "CA00000AA", birthDate: "1990-01-31", expiryDate: "2031-01-31"),
          challenge: challenge) { result in /* ... */ }
```

- Exactly one access method is used per read. There is no BAC fallback.
- The challenge is passed as raw bytes (1 to 255 bytes) and sent to the card unchanged.
- The completion is called once, on the main thread. `onStep` reports progress.
- `cancel()` stops the running read; the completion receives `CANCELLED`.
- The texts of the NFC sheet can be changed with `L2PlusNfcMessages` (Italian by default).

### Output

```json
{
  "mrtd": { "dg1": "...", "dg11": "...", "sod_mrtd": "..." },
  "ias":  { "ias_pk": "...", "sod_ias": "...", "challenge_signed": "..." }
}
```

Each value is the standard Base64 encoding, with padding, of the bytes read from the card.
`L2PlusResult` is also `Codable`.

### Local checks

Before returning, the SDK checks:

- the MRTD SOD signature and the Document Signer chain to the configured CSCA certificates;
- the DG1 and DG11 hashes against the SOD;
- the IAS SOD signature and chain, and that it covers the IAS public key.

These checks do not replace the ones done by the PID Provider. Validation uses the current date.
`iasTrustAnchors` defaults to the MRTD anchors; CRLs are optional.

`L2PlusTrustConfig.bundledCscaCertificates()` returns the Italian CSCA certificates shipped with the
package. They are meant for testing: a production app should supply up-to-date trust material.

### Errors

`L2PlusError` carries a stable `code` (same names on Android), the `phase` where it happened, the
suggested `action` for the app and, when relevant, the card status word `sw`. Messages never contain
personal data, access data or keys.

| Action | Codes |
|---|---|
| `fixInput` | `INVALID_CAN`, `INVALID_MRZ_DATA`, `INVALID_CHALLENGE` |
| `checkAccessData` | `PACE_FAILED` |
| `retryTap` | `TAG_LOST`, `SECURE_MESSAGING_ERROR`, `MRTD_READ_FAILED`, `IAS_READ_FAILED`, `IAS_SIGN_FAILED` |
| `unsupported` | `NFC_NOT_AVAILABLE`, `TAG_NOT_SUPPORTED`, `PACE_NOT_SUPPORTED`, `CIE_TYPE_UNKNOWN` |
| `updateTrustMaterial` | `MISSING_TRUST_ANCHORS`, `TRUST_ANCHOR_NOT_FOUND` |
| `rejectDocument` | `SOD_MRTD_INVALID`, `DG_HASH_MISMATCH`, `SOD_IAS_INVALID`, `IAS_KEY_NOT_BOUND`, `CERTIFICATE_CHAIN_INVALID` |
| `none` | `CANCELLED`, `ALREADY_RUNNING` |
| `contactSupport` | `INTERNAL_ERROR` |

## Demo app

`ios/Demo/L2PlusDemo.xcodeproj` is a minimal SwiftUI app that runs a read and shows the JSON.
Select your team in *Signing & Capabilities* and run it on a device. The project is generated
from `ios/Demo/project.yml` with [XcodeGen](https://github.com/yonaskolb/XcodeGen).

## Tests

```sh
brew install openssl@3
ios/Tests/run.sh
```

The tests run on macOS without a card. They cover secure messaging (ICAO 9303-11 Appendix D),
AES-CMAC (RFC 4493), PACE ECDH and DH Generic Mapping (BSI worked example, including a full
replayed exchange), SOD verification with a throwaway PKI, MRZ handling and input validation.

## Project layout

```
Package.swift              Swift package manifest (repository root)
ios/Sources/L2PlusSDK      Swift API, NFC session, PACE, secure messaging, IAS, SOD checks
ios/Sources/L2PlusCrypto   OpenSSL-based CMS verification and PACE key agreement
ios/Vendor/OpenSSL         OpenSSL 3.5 (libcrypto) as XCFramework, with its build script
ios/Demo                   Sample app
ios/Tests                  Command-line tests
```

## Third-party software

- [OpenSSL](https://www.openssl.org) 3.5, Apache License 2.0 (`ios/Vendor/OpenSSL/LICENSE.txt`).
  Rebuild it with `ios/Vendor/OpenSSL/build.sh`.

## License

Copyright 2026 Istituto Poligrafico e Zecca dello Stato S.p.A.

Licensed under the [Apache License, Version 2.0](../LICENSE).

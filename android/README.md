# L2+ SDK for Android

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

- Android 8.0 (API 26) or later, device with NFC
- JDK 17 or later to build

## Modules

| Module | Content |
|---|---|
| `sdk` | The library (`it.ipzs.l2plus`) |
| `demo` | Minimal app that runs a read and shows the JSON |

To use the library from another project, include the `sdk` module or publish it to your Maven
repository. It depends only on BouncyCastle (`bcprov`, `bcpkix`).

## Usage

```kotlin
val sdk = L2PlusSdk(activity, L2PlusTrustConfig(cscaCertificates))

sdk.start(L2PlusAccess.Can("123456"), challenge, object : L2PlusCallback {
    override fun onSuccess(result: L2PlusResult) {
        val json = result.toJson()    // goes into the mrtd_validation_jwt payload
    }

    override fun onError(error: L2PlusException) {
        Log.w(TAG, "${error.code} ${error.action}")
    }
})
```

With the MRZ data returned by the Ministry of the Interior service:

```kotlin
sdk.start(L2PlusAccess.Mrz("CA00000AA", "1990-01-31", "2031-01-31"), challenge, callback)
```

- Exactly one access method is used per read. There is no BAC fallback.
- The challenge is passed as raw bytes (1 to 255 bytes) and sent to the card unchanged.
- The SDK uses NFC reader mode on the given activity while a read is running.
- Exactly one of `onSuccess` and `onError` is called, once, on the main thread. `onStep` reports progress.
- `cancel()` stops the running read; the callback receives `CANCELLED`. Call it from `onPause`.

### Output

```json
{
  "mrtd": { "dg1": "...", "dg11": "...", "sod_mrtd": "..." },
  "ias":  { "ias_pk": "...", "sod_ias": "...", "challenge_signed": "..." }
}
```

Each value is the standard Base64 encoding, with padding, of the bytes read from the card.

### Local checks

Before returning, the SDK checks:

- the MRTD SOD signature and the Document Signer chain to the configured CSCA certificates;
- the DG1 and DG11 hashes against the SOD;
- the IAS SOD signature and chain, and that it covers the IAS public key.

These checks do not replace the ones done by the PID Provider. Validation uses the current date.
`iasTrustAnchors` defaults to the MRTD anchors; CRLs are optional.

`L2PlusSdk.bundledCscaCertificates(context)` returns the Italian CSCA certificates shipped in the
library assets. They are meant for testing: a production app should supply up-to-date trust material.

### Errors

`L2PlusException` carries a stable `code` (same names on iOS), the `phase` where it happened, the
suggested `action` for the app and, when relevant, the card status word `sw`. Messages never contain
personal data, access data or keys.

| Action | Codes |
|---|---|
| `FIX_INPUT` | `INVALID_CAN`, `INVALID_MRZ_DATA`, `INVALID_CHALLENGE` |
| `CHECK_ACCESS_DATA` | `PACE_FAILED` |
| `RETRY_TAP` | `TAG_LOST`, `SECURE_MESSAGING_ERROR`, `MRTD_READ_FAILED`, `IAS_READ_FAILED`, `IAS_SIGN_FAILED` |
| `ENABLE_NFC` | `NFC_DISABLED` |
| `UNSUPPORTED` | `NFC_NOT_AVAILABLE`, `TAG_NOT_SUPPORTED`, `PACE_NOT_SUPPORTED`, `CIE_TYPE_UNKNOWN` |
| `UPDATE_TRUST_MATERIAL` | `MISSING_TRUST_ANCHORS`, `TRUST_ANCHOR_NOT_FOUND` |
| `REJECT_DOCUMENT` | `SOD_MRTD_INVALID`, `DG_HASH_MISMATCH`, `SOD_IAS_INVALID`, `IAS_KEY_NOT_BOUND`, `CERTIFICATE_CHAIN_INVALID` |
| `NONE` | `CANCELLED`, `ALREADY_RUNNING` |
| `CONTACT_SUPPORT` | `INTERNAL_ERROR` |

## Build and tests

```sh
cd android
./gradlew :sdk:testDebugUnitTest :demo:assembleDebug
```

The unit tests run on the JVM without a card. They cover secure messaging (ICAO 9303-11 Appendix D),
PACE ECDH and DH Generic Mapping (BSI worked example, including a full replayed exchange), SOD
verification with a throwaway PKI, MRZ handling and input validation.

## Third-party software

- [Bouncy Castle](https://www.bouncycastle.org) 1.81 (`bcprov`, `bcpkix`), MIT License.
  Resolved from Maven Central, not included in the repository.

## License

Copyright 2026 Istituto Poligrafico e Zecca dello Stato S.p.A.

Licensed under the [Apache License, Version 2.0](../LICENSE).

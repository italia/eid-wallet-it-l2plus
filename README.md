# IT-Wallet L2+ SDK

Libraries for iOS and Android that read from an Italian electronic identity card (CIE) the evidence
required by the IT-Wallet "Level 2 Plus" (L2+) PID issuance flow, in a single NFC session:

| Card application | Operation | Output |
|---|---|---|
| eMRTD | PACE with CAN or MRZ data, then read | `dg1`, `dg11`, `sod_mrtd` |
| IAS | read | `ias_pk`, `sod_ias` |
| IAS | Internal Authentication of the backend challenge | `challenge_signed` |

The result maps one-to-one to the `mrtd` and `ias` objects of the `mrtd_validation_jwt` payload
described in the [IT-Wallet technical specification](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuance-l2plus.html).

Both SDKs expose the same flow, the same output and the same error codes.

| Platform | Folder | Documentation |
|---|---|---|
| iOS 15+ | [`ios`](ios) | [ios/README.md](ios/README.md) |
| Android 8.0+ | [`android`](android) | [android/README.md](android/README.md) |

The Swift package manifest is at the root of the repository, so the iOS SDK can be added with
Swift Package Manager directly from this URL.

## License

Copyright 2026 Istituto Poligrafico e Zecca dello Stato S.p.A.

Licensed under the [Apache License, Version 2.0](LICENSE).

//
//  L2PlusSodVerifier.swift
//  SOD checks: signature and chain (OpenSSL), then the signed hashes.
//

import Foundation
import CommonCrypto
#if canImport(L2PlusCrypto)
import L2PlusCrypto
#endif

enum L2PlusSodVerifier {

    struct SignedHashes {
        let digest: ([UInt8]) -> [UInt8]
        let hashes: [Int: [UInt8]]
    }

    static func verify(_ sod: [UInt8], anchors: [Data], crls: [Data], invalid: L2PlusErrorCode) throws -> SignedHashes {
        let cms = try unwrap(sod, invalid)
        let r = L2PlusCms.verify(Data(cms), anchors: anchors, crls: crls)
        switch r.status {
        case .ok: break
        case .anchorNotFound: throw L2PlusError(.TRUST_ANCHOR_NOT_FOUND, "No trust anchor for the Document Signer")
        case .chainInvalid: throw L2PlusError(.CERTIFICATE_CHAIN_INVALID, "Invalid Document Signer chain")
        case .signatureInvalid: throw L2PlusError(invalid, "Invalid SOD signature")
        default: throw L2PlusError(invalid, "Invalid SOD structure")
        }
        guard let content = r.content else { throw L2PlusError(invalid, "Missing signed content") }
        return try parseSecurityObject([UInt8](content), invalid)
    }

    private static func unwrap(_ sod: [UInt8], _ code: L2PlusErrorCode) throws -> [UInt8] {
        guard let first = sod.first else { throw L2PlusError(code, "Empty SOD") }
        guard first == 0x77 else { return sod }
        guard let h = try? L2PlusTlv.header(sod), h.totalLength <= sod.count else { throw L2PlusError(code, "Truncated SOD") }
        return Array(sod[h.headerLength..<h.totalLength])
    }

    /// LDSSecurityObject: SEQUENCE { version, AlgorithmIdentifier, SEQUENCE OF { INTEGER, OCTET STRING }, ... }
    static func parseSecurityObject(_ content: [UInt8], _ code: L2PlusErrorCode) throws -> SignedHashes {
        func fail() -> L2PlusError { L2PlusError(code, "Cannot parse SOD content") }
        guard let outer = try? L2PlusTlv.children(content, expectTag: 0x30), outer.count >= 3,
              outer[0].tag == 0x02, outer[1].tag == 0x30, outer[2].tag == 0x30,
              let alg = try? L2PlusTlv.children(outer[1].full, expectTag: 0x30), let oid = alg.first, oid.tag == 0x06,
              let digest = digestFunction(oid: oid.value),
              let entries = try? L2PlusTlv.children(outer[2].full, expectTag: 0x30) else { throw fail() }
        var hashes: [Int: [UInt8]] = [:]
        for entry in entries {
            guard let parts = try? L2PlusTlv.children(entry.full, expectTag: 0x30), parts.count == 2,
                  parts[0].tag == 0x02, parts[1].tag == 0x04, !parts[0].value.isEmpty, parts[0].value.count <= 4 else { throw fail() }
            let number = parts[0].value.reduce(0) { $0 << 8 | Int($1) }
            guard hashes[number] == nil else { throw fail() }
            hashes[number] = parts[1].value
        }
        guard !hashes.isEmpty else { throw fail() }
        return SignedHashes(digest: digest, hashes: hashes)
    }

    private static func digestFunction(oid: [UInt8]) -> (([UInt8]) -> [UInt8])? {
        func make(_ len: Int32, _ f: @escaping (UnsafeRawPointer?, CC_LONG, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?) -> ([UInt8]) -> [UInt8] {
            return { data in
                var out = [UInt8](repeating: 0, count: Int(len))
                _ = f(data, CC_LONG(data.count), &out)
                return out
            }
        }
        switch l2pHexString(oid) {
        case "2B0E03021A": return make(CC_SHA1_DIGEST_LENGTH, CC_SHA1)
        case "608648016503040204": return make(CC_SHA224_DIGEST_LENGTH, CC_SHA224)
        case "608648016503040201": return make(CC_SHA256_DIGEST_LENGTH, CC_SHA256)
        case "608648016503040202": return make(CC_SHA384_DIGEST_LENGTH, CC_SHA384)
        case "608648016503040203": return make(CC_SHA512_DIGEST_LENGTH, CC_SHA512)
        default: return nil
        }
    }
}

//
//  L2PlusCipher.swift
//  PACE cipher suites (ICAO 9303-11 §9.2, §9.8): KDF, CBC, retail MAC and AES-CMAC.
//

import Foundation
import CommonCrypto

enum L2PlusCipher {
    case tripleDes, aes128, aes192, aes256

    /// Last arc of the PACE OID.
    init?(oidSuffix: UInt8) {
        switch oidSuffix {
        case 1: self = .tripleDes
        case 2: self = .aes128
        case 3: self = .aes192
        case 4: self = .aes256
        default: return nil
        }
    }

    var blockSize: Int { self == .tripleDes ? 8 : 16 }

    private var keyLength: Int {
        switch self {
        case .tripleDes, .aes128: return 16
        case .aes192: return 24
        case .aes256: return 32
        }
    }

    /// KDF(K, c) = H(K || c), truncated to the key length. c = 1 (enc), 2 (mac), 3 (password).
    func kdf(_ secret: [UInt8], counter: UInt8) -> [UInt8] {
        let input = secret + [0, 0, 0, counter]
        var digest: [UInt8]
        switch self {
        case .tripleDes, .aes128:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            _ = CC_SHA1(input, CC_LONG(input.count), &digest)
        case .aes192, .aes256:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            _ = CC_SHA256(input, CC_LONG(input.count), &digest)
        }
        return Array(digest[0..<keyLength])
    }

    /// CBC without padding. Returns nil if the input is not block aligned.
    func encrypt(key: [UInt8], data: [UInt8], iv: [UInt8]? = nil) -> [UInt8]? {
        cbc(CCOperation(kCCEncrypt), key: key, data: data, iv: iv ?? [UInt8](repeating: 0, count: blockSize))
    }

    func decrypt(key: [UInt8], data: [UInt8], iv: [UInt8]? = nil) -> [UInt8]? {
        cbc(CCOperation(kCCDecrypt), key: key, data: data, iv: iv ?? [UInt8](repeating: 0, count: blockSize))
    }

    /// Secure messaging IV: E(K_enc, SSC) for AES, zero for 3DES.
    func smIv(kEnc: [UInt8], ssc: [UInt8]) -> [UInt8]? {
        if self == .tripleDes { return [UInt8](repeating: 0, count: 8) }
        return Self.crypt(CCOperation(kCCEncrypt), alg: CCAlgorithm(kCCAlgorithmAES), key: kEnc, iv: nil, data: ssc, ecb: true)
    }

    /// 8-byte MAC: retail MAC (ISO 9797-1 alg. 3) for 3DES, truncated CMAC for AES.
    /// For 3DES the input must already be padded.
    func mac(key: [UInt8], data: [UInt8]) -> [UInt8]? {
        switch self {
        case .tripleDes:
            guard key.count == 16, !data.isEmpty, data.count % 8 == 0 else { return nil }
            let k1 = Array(key[0..<8]), k2 = Array(key[8..<16])
            let des = CCAlgorithm(kCCAlgorithmDES)
            guard let cbc = Self.crypt(CCOperation(kCCEncrypt), alg: des, key: k1, iv: [UInt8](repeating: 0, count: 8), data: data),
                  let d = Self.crypt(CCOperation(kCCDecrypt), alg: des, key: k2, iv: nil, data: Array(cbc[(cbc.count - 8)...]), ecb: true)
            else { return nil }
            return Self.crypt(CCOperation(kCCEncrypt), alg: des, key: k1, iv: nil, data: d, ecb: true)
        case .aes128, .aes192, .aes256:
            return Self.aesCmac(key: key, data: data).map { Array($0[0..<8]) }
        }
    }

    /// PACE authentication token over the public key data object.
    func authToken(kMac: [UInt8], authData: [UInt8]) -> [UInt8]? {
        mac(key: kMac, data: self == .tripleDes ? l2pPad(authData, blockSize: 8) : authData)
    }

    /// AES-CMAC (RFC 4493).
    static func aesCmac(key: [UInt8], data: [UInt8]) -> [UInt8]? {
        let aes = CCAlgorithm(kCCAlgorithmAES)
        func block(_ b: [UInt8]) -> [UInt8]? { crypt(CCOperation(kCCEncrypt), alg: aes, key: key, iv: nil, data: b, ecb: true) }
        func dbl(_ b: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 16)
            var carry: UInt8 = 0
            for i in (0..<16).reversed() { out[i] = b[i] << 1 | carry; carry = b[i] >> 7 }
            if b[0] & 0x80 != 0 { out[15] ^= 0x87 }
            return out
        }
        guard let l = block([UInt8](repeating: 0, count: 16)) else { return nil }
        let k1 = dbl(l), k2 = dbl(k1)
        let n = max(1, (data.count + 15) / 16)
        var last: [UInt8]
        if !data.isEmpty && data.count % 16 == 0 {
            last = Array(data[(data.count - 16)...])
            for i in 0..<16 { last[i] ^= k1[i] }
        } else {
            last = Array(data[(16 * (n - 1))...]) + [0x80]
            last += [UInt8](repeating: 0, count: 16 - last.count)
            for i in 0..<16 { last[i] ^= k2[i] }
        }
        var x = [UInt8](repeating: 0, count: 16)
        for i in 0..<(n - 1) {
            var b = Array(data[(16 * i)..<(16 * i + 16)])
            for j in 0..<16 { b[j] ^= x[j] }
            guard let y = block(b) else { return nil }
            x = y
        }
        for j in 0..<16 { last[j] ^= x[j] }
        return block(last)
    }

    private func cbc(_ op: CCOperation, key: [UInt8], data: [UInt8], iv: [UInt8]) -> [UInt8]? {
        guard data.count % blockSize == 0 else { return nil }
        switch self {
        case .tripleDes:
            guard key.count == 16 else { return nil }
            return Self.crypt(op, alg: CCAlgorithm(kCCAlgorithm3DES), key: key + key[0..<8], iv: iv, data: data)
        case .aes128, .aes192, .aes256:
            return Self.crypt(op, alg: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv, data: data)
        }
    }

    private static func crypt(_ op: CCOperation, alg: CCAlgorithm, key: [UInt8], iv: [UInt8]?, data: [UInt8], ecb: Bool = false) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: data.count + 32)
        var moved = 0
        let options = CCOptions(ecb ? kCCOptionECBMode : 0)
        let status = CCCrypt(op, alg, options, key, key.count, iv, data, data.count, &out, out.count, &moved)
        guard status == kCCSuccess else { return nil }
        return Array(out[0..<moved])
    }
}

/// ISO/IEC 9797-1 padding method 2.
func l2pPad(_ d: [UInt8], blockSize: Int) -> [UInt8] {
    var out = d + [0x80]
    while out.count % blockSize != 0 { out.append(0) }
    return out
}

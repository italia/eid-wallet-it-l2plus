//
//  L2PlusPace.swift
//  PACE with Generic Mapping (ICAO 9303-11 §4.4), using the CAN or the MRZ data.
//  There is no BAC fallback: if PACE is missing or fails, the read stops.
//

import Foundation
import CommonCrypto
#if canImport(L2PlusCrypto)
import L2PlusCrypto
#endif

/// PACEInfo with Generic Mapping and standardized domain parameters.
struct L2PlusPaceInfo {
    /// OID value bytes, as sent in MSE:Set AT.
    let oid: [UInt8]
    let parameterId: Int
    let cipher: L2PlusCipher
    let group: L2PlusPaceGroup

    private static let paceDhGm = l2pHex("04007F000702020401")
    private static let paceEcdhGm = l2pHex("04007F000702020402")

    /// First supported PACEInfo found in EF.CardAccess.
    static func select(cardAccess: [UInt8]) -> L2PlusPaceInfo? {
        guard let infos = try? L2PlusTlv.children(cardAccess, expectTag: 0x31) else { return nil }
        for info in infos where info.tag == 0x30 {
            guard let fields = try? L2PlusTlv.children(info.full, expectTag: 0x30), fields.count >= 3,
                  fields[0].tag == 0x06, fields[1].tag == 0x02, fields[2].tag == 0x02 else { continue }
            let oid = fields[0].value
            guard oid.count == 10 else { continue }
            let prefix = Array(oid[0..<9])
            let isEc = prefix == paceEcdhGm
            guard isEc || prefix == paceDhGm,
                  fields[1].value == [0x02],
                  fields[2].value.count <= 2,
                  let cipher = L2PlusCipher(oidSuffix: oid[9]) else { continue }
            let parameterId = fields[2].value.reduce(0) { $0 << 8 | Int($1) }
            guard let group = L2PlusPaceGroup(parameterId: parameterId), group.isEllipticCurve == isEc else { continue }
            return L2PlusPaceInfo(oid: oid, parameterId: parameterId, cipher: cipher, group: group)
        }
        return nil
    }

    func authData(group: L2PlusPaceGroup, publicKey: [UInt8]) -> [UInt8] {
        L2PlusTlv.encode(0x7F49, L2PlusTlv.encode(0x06, oid) + L2PlusTlv.encode(group.isEllipticCurve ? 0x86 : 0x84, publicKey))
    }
}

enum L2PlusPace {

    private static let pwdMrz: UInt8 = 0x01
    private static let pwdCan: UInt8 = 0x02

    typealias KeyGenerator = (L2PlusPaceGroup) -> Data?

    static func establish(_ card: L2PlusCardIO, access: L2PlusRequest.ValidAccess,
                          keyGenerator: KeyGenerator = { $0.generatePrivateKey() }) async throws -> L2PlusSecureMessaging {
        let info = try await readPaceInfo(card)

        var password: [UInt8]
        let pwdRef: UInt8
        switch access {
        case .can(let can):
            password = Array(can.utf8); pwdRef = pwdCan
        case .mrz(let mrz):
            password = sha1(Array(mrz.utf8)); pwdRef = pwdMrz
        }
        defer { for i in password.indices { password[i] = 0 } }

        let mse = L2PlusTlv.encode(0x80, info.oid) + L2PlusTlv.encode(0x83, [pwdRef])
        try card.expectOk(try await card.plain(L2PlusApdu.command(0x00, 0x22, 0xC1, 0xA4, data: mse)), .PACE_FAILED, "MSE:Set AT")

        // Step 1: encrypted nonce.
        let r1 = try card.expectOk(try await card.plain(ga(chained: true, [])), .PACE_FAILED, "General Authenticate 1")
        var nonce = try decryptNonce(info.cipher, password: password, encrypted: try dynamicObject(r1.data, tag: 0x80))
        defer { for i in nonce.indices { nonce[i] = 0 } }

        // Step 2: mapping.
        guard let mapKey = keyGenerator(info.group),
              let mapPublic = info.group.publicKey(forPrivateKey: mapKey) else { throw failure("Key generation failed") }
        let r2 = try card.expectOk(try await card.plain(ga(chained: true, L2PlusTlv.encode(0x81, [UInt8](mapPublic)))),
                                   .PACE_FAILED, "General Authenticate 2")
        guard let group = info.group.map(withNonce: Data(nonce), privateKey: mapKey,
                                         peerPublicKey: Data(try dynamicObject(r2.data, tag: 0x82))) else {
            throw failure("Mapping failed")
        }

        // Step 3: key agreement on the mapped group.
        guard let ephKey = keyGenerator(group),
              let ephPublicData = group.publicKey(forPrivateKey: ephKey) else { throw failure("Key generation failed") }
        let ephPublic = [UInt8](ephPublicData)
        let r3 = try card.expectOk(try await card.plain(ga(chained: true, L2PlusTlv.encode(0x83, ephPublic))),
                                   .PACE_FAILED, "General Authenticate 3")
        let cardEphPublic = try dynamicObject(r3.data, tag: 0x84)
        guard cardEphPublic != ephPublic else { throw failure("Invalid card ephemeral key") }
        guard let sharedData = group.sharedSecret(withPrivateKey: ephKey, peerPublicKey: Data(cardEphPublic)) else {
            throw failure("Key agreement failed")
        }
        var shared = [UInt8](sharedData)
        defer { for i in shared.indices { shared[i] = 0 } }
        let kEnc = info.cipher.kdf(shared, counter: 1)
        let kMac = info.cipher.kdf(shared, counter: 2)

        // Step 4: mutual authentication tokens.
        guard let token = info.cipher.authToken(kMac: kMac, authData: info.authData(group: group, publicKey: cardEphPublic)),
              let expected = info.cipher.authToken(kMac: kMac, authData: info.authData(group: group, publicKey: ephPublic)) else {
            throw failure("Token computation failed")
        }
        let r4 = try card.expectOk(try await card.plain(ga(chained: false, L2PlusTlv.encode(0x85, token))),
                                   .PACE_FAILED, "General Authenticate 4")
        guard constantTimeEqual(expected, try dynamicObject(r4.data, tag: 0x86)) else {
            throw failure("Invalid card authentication token")
        }
        return L2PlusSecureMessaging(cipher: info.cipher, kEnc: kEnc, kMac: kMac)
    }

    static func decryptNonce(_ cipher: L2PlusCipher, password: [UInt8], encrypted: [UInt8]) throws -> [UInt8] {
        var kPi = cipher.kdf(password, counter: 3)
        defer { for i in kPi.indices { kPi[i] = 0 } }
        guard let nonce = cipher.decrypt(key: kPi, data: encrypted) else { throw failure("Invalid encrypted nonce") }
        return nonce
    }

    /// EF.CardAccess (FID 011C), read in clear.
    private static func readPaceInfo(_ card: L2PlusCardIO) async throws -> L2PlusPaceInfo {
        let select = try await card.plain(L2PlusApdu.command(0x00, 0xA4, 0x02, 0x0C, data: [0x01, 0x1C]))
        guard select.isSuccess else { throw L2PlusError(.PACE_NOT_SUPPORTED, "EF.CardAccess not found", sw: select.sw) }
        let content = try await card.readTlvFile(.PACE_NOT_SUPPORTED, secure: false)
        guard let info = L2PlusPaceInfo.select(cardAccess: content) else {
            throw L2PlusError(.PACE_NOT_SUPPORTED, "No supported PACEInfo")
        }
        return info
    }

    private static func dynamicObject(_ response: [UInt8], tag: UInt8) throws -> [UInt8] {
        guard let outer = try? L2PlusTlv.children(response, expectTag: 0x7C), let obj = outer.first, obj.tag == tag else {
            throw failure("Invalid General Authenticate response")
        }
        return obj.value
    }

    /// General Authenticate with dynamic authentication data (7C). Uses an extended APDU when needed.
    private static func ga(chained: Bool, _ dynamicData: [UInt8]) -> [UInt8] {
        let cla: UInt8 = chained ? 0x10 : 0x00
        let data = L2PlusTlv.encode(0x7C, dynamicData)
        if data.count <= 255 { return L2PlusApdu.command(cla, 0x86, 0x00, 0x00, data: data, le: 0) }
        return [cla, 0x86, 0x00, 0x00, 0x00, UInt8(data.count >> 8), UInt8(data.count & 0xFF)] + data + [0x00, 0x00]
    }

    private static func sha1(_ data: [UInt8]) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        _ = CC_SHA1(data, CC_LONG(data.count), &digest)
        return digest
    }

    private static func failure(_ message: String) -> L2PlusError { L2PlusError(.PACE_FAILED, message) }
}

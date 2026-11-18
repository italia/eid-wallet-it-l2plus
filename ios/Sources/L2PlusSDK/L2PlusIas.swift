//
//  L2PlusIas.swift
//  IAS application of the CIE: anti-cloning public key (EF 1005), IAS SOD (EF 1006) and
//  Internal Authentication of the challenge. All commands are sent in clear; no PIN is involved.
//

import Foundation

enum L2PlusIas {

    enum Vendor { case nxp, gemalto, st }

    struct Evidence {
        let publicKeyRaw: [UInt8]
        let publicKey: [UInt8]
        let sod: [UInt8]
        let signedChallenge: [UInt8]
    }

    static let iasAid = l2pHex("A0000000308000000009816001")
    static let cieAid = l2pHex("A00000000039")
    private static let efAtr: UInt16 = 0x2F01
    private static let efIntKpub: UInt16 = 0x1005
    private static let efSodIas: UInt16 = 0x1006
    private static let intAuthKeyId: UInt8 = 0x83

    // Byte sequences that identify the chip manufacturer in EF.ATR.
    private static let nxpAtr = l2pHex("80 00 43 01 B8 46 04 10 10 10 10 47 03 94")
    private static let gemaltoAtr = l2pHex("49 61 73 45 63 63 52 6F 6F 74") // "IasEccRoot"
    private static let gemalto2Atr = l2pHex("47 03 94 41 C0")
    private static let stAtr = l2pHex(
        "80 00 43 01 B9 46 04 00 00 00 10 47 03 94 01 81 4F 0C A0 00 00 00 95 00 00 00 00 8A 00 01 " +
        "E0 10 02 02 00 FF 02 02 00 FF 02 02 01 00 02 02 01 00 78 08 06 06 2B 81 22 F8 78 02 82 02 90 00")

    static func read(_ card: L2PlusCardIO, challenge: [UInt8], onSigning: () -> Void) async throws -> Evidence {
        // Leave the eMRTD secure messaging session and go back to the MF.
        card.sm?.destroy()
        card.sm = nil
        try card.expectOk(try await card.plain(L2PlusApdu.command(0x00, 0xA4, 0x00, 0x00, data: [0x3F, 0x00])), .IAS_READ_FAILED, "Select MF")

        let atr = try await card.readIasFile(efAtr, .CIE_TYPE_UNKNOWN)
        guard let vendor = vendor(fromAtr: atr) else {
            throw L2PlusError(.CIE_TYPE_UNKNOWN, "Unknown CIE manufacturer")
        }
        // NXP chips expose IAS at the MF, the others by AID.
        let selectIas: [UInt8]
        switch vendor {
        case .nxp: selectIas = L2PlusApdu.command(0x00, 0xA4, 0x00, 0x00)
        case .gemalto, .st: selectIas = L2PlusApdu.command(0x00, 0xA4, 0x04, 0x0C, data: iasAid)
        }
        try card.expectOk(try await card.plain(selectIas), .IAS_READ_FAILED, "Select IAS application")
        try card.expectOk(try await card.plain(L2PlusApdu.command(0x00, 0xA4, 0x04, 0x0C, data: cieAid)), .IAS_READ_FAILED, "Select DF CIE")

        let keyRaw = try await card.readIasFile(efIntKpub, .IAS_READ_FAILED)
        let key = try L2PlusCardIO.derObject(keyRaw, .IAS_READ_FAILED)
        let sod = try L2PlusCardIO.derObject(try await card.readIasFile(efSodIas, .IAS_READ_FAILED), .IAS_READ_FAILED)

        onSigning()
        // MSE:Set: algorithm 80 01 02, key reference 84 01 83.
        try card.expectOk(try await card.plain(L2PlusApdu.command(0x00, 0x22, 0x41, 0xA4, data: [0x80, 0x01, 0x02, 0x84, 0x01, intAuthKeyId])),
                          .IAS_SIGN_FAILED, "MSE:Set Internal Authentication")
        // INTERNAL AUTHENTICATE without Le: the card answers with 61xx.
        let signed = try card.expectOk(try await card.plain(L2PlusApdu.command(0x00, 0x88, 0x00, 0x00, data: challenge)),
                                       .IAS_SIGN_FAILED, "Internal Authenticate").data
        guard !signed.isEmpty else { throw L2PlusError(.IAS_SIGN_FAILED, "Empty signature") }
        return Evidence(publicKeyRaw: keyRaw, publicKey: key, sod: sod, signedChallenge: signed)
    }

    static func vendor(fromAtr atr: [UInt8]) -> Vendor? {
        if contains(atr, nxpAtr) { return .nxp }
        if contains(atr, gemaltoAtr) || contains(atr, gemalto2Atr) { return .gemalto }
        if contains(atr, stAtr) { return .st }
        return nil
    }

    private static func contains(_ hay: [UInt8], _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, needle.count <= hay.count else { return false }
        for i in 0...(hay.count - needle.count) where Array(hay[i..<(i + needle.count)]) == needle { return true }
        return false
    }
}

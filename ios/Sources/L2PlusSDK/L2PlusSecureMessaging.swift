//
//  L2PlusSecureMessaging.swift
//  Secure messaging (ICAO 9303-11 §9.8), one instance per PACE session.
//

import Foundation

/// A protected response is accepted only with DO'99' and a valid DO'8E'.
final class L2PlusSecureMessaging {
    private let cipher: L2PlusCipher
    private var kEnc: [UInt8]
    private var kMac: [UInt8]
    private var ssc: [UInt8]

    init(cipher: L2PlusCipher, kEnc: [UInt8], kMac: [UInt8], ssc: [UInt8]? = nil) {
        self.cipher = cipher
        self.kEnc = kEnc
        self.kMac = kMac
        self.ssc = ssc ?? [UInt8](repeating: 0, count: cipher.blockSize)
        precondition(self.ssc.count == cipher.blockSize)
    }

    /// Protects a short plain APDU.
    func wrap(_ command: [UInt8]) throws -> [UInt8] {
        precondition(command.count >= 4)
        let header: [UInt8] = [command[0] | 0x0C, command[1], command[2], command[3]]
        var data: [UInt8] = []
        var le: UInt8?
        if command.count == 5 {
            le = command[4]
        } else if command.count > 5 {
            let lc = Int(command[4])
            precondition(command.count == 5 + lc || command.count == 6 + lc)
            data = Array(command[5..<(5 + lc)])
            if command.count == 6 + lc { le = command[5 + lc] }
        }
        increment()
        var dos: [UInt8] = []
        if !data.isEmpty {
            guard let iv = cipher.smIv(kEnc: kEnc, ssc: ssc),
                  let enc = cipher.encrypt(key: kEnc, data: pad(data), iv: iv) else { throw smError("Encryption failed") }
            // Odd INS uses DO'85' (no padding indicator), even INS uses DO'87'.
            dos += command[1] % 2 == 0 ? L2PlusTlv.encode(0x87, [0x01] + enc) : L2PlusTlv.encode(0x85, enc)
        }
        if let le = le { dos += [0x97, 0x01, le] }
        guard let mac = cipher.mac(key: kMac, data: pad(ssc + pad(header) + dos)) else { throw smError("MAC failed") }
        let body = dos + [0x8E, 0x08] + mac
        guard body.count <= 255 else { throw smError("Protected APDU too long for a short APDU") }
        return header + [UInt8(body.count)] + body + [0x00]
    }

    /// Checks and decrypts a protected response; returns the plain data and the status word found in DO'99'.
    func unwrap(_ response: L2PlusResponse) throws -> L2PlusResponse {
        increment()
        if !response.isSuccess && response.data.isEmpty {
            // Plain error: the card has closed the session, no data is accepted.
            return L2PlusResponse(data: [], sw: response.sw)
        }
        let raw = response.data
        var pos = 0
        var do87: [UInt8]?
        var do99: [UInt8]?
        var do8e: [UInt8]?
        var macInput: [UInt8] = []
        do {
            while pos < raw.count {
                let tag = raw[pos]
                let h = try L2PlusTlv.header(raw, at: pos)
                guard pos + h.totalLength <= raw.count else { throw smError("Truncated data object") }
                let full = Array(raw[pos..<(pos + h.totalLength)])
                let value = Array(raw[(pos + h.headerLength)..<(pos + h.totalLength)])
                switch tag {
                case 0x87, 0x85:
                    guard do87 == nil, do99 == nil else { throw smError("Duplicate data object") }
                    do87 = full; macInput += full
                case 0x99:
                    guard do99 == nil else { throw smError("Duplicate data object") }
                    do99 = value; macInput += full
                case 0x8E:
                    guard pos + h.totalLength == raw.count else { throw smError("Data after MAC") }
                    do8e = value
                default:
                    throw smError("Unexpected data object")
                }
                pos += h.totalLength
            }
        } catch let e as L2PlusError {
            throw e
        } catch {
            throw smError("Invalid secure messaging structure")
        }
        guard let mac = do8e else { throw smError("Missing MAC") }
        guard let sw = do99, sw.count == 2 else { throw smError("Missing protected status word") }
        guard let expected = cipher.mac(key: kMac, data: pad(ssc + macInput)),
              mac.count == 8, constantTimeEqual(expected, mac) else { throw smError("Invalid MAC") }

        var plain: [UInt8] = []
        if let obj = do87 {
            let h = try L2PlusTlv.header(obj)
            var value = Array(obj[h.headerLength...])
            if obj[0] == 0x87 {
                guard value.first == 0x01 else { throw smError("Invalid padding indicator") }
                value.removeFirst()
            }
            guard !value.isEmpty, let iv = cipher.smIv(kEnc: kEnc, ssc: ssc),
                  let decrypted = cipher.decrypt(key: kEnc, data: value, iv: iv) else { throw smError("Invalid cryptogram") }
            plain = try unpad(decrypted)
        }
        return L2PlusResponse(data: plain, sw: UInt16(sw[0]) << 8 | UInt16(sw[1]))
    }

    /// Wipes the session keys.
    func destroy() {
        for i in kEnc.indices { kEnc[i] = 0 }
        for i in kMac.indices { kMac[i] = 0 }
        for i in ssc.indices { ssc[i] = 0 }
    }

    private func increment() {
        for i in ssc.indices.reversed() {
            ssc[i] = ssc[i] &+ 1
            if ssc[i] != 0 { return }
        }
    }

    private func pad(_ d: [UInt8]) -> [UInt8] { l2pPad(d, blockSize: cipher.blockSize) }

    private func unpad(_ d: [UInt8]) throws -> [UInt8] {
        var i = d.count - 1
        while i >= 0 && d[i] == 0 { i -= 1 }
        guard i >= 0, d[i] == 0x80 else { throw smError("Invalid padding") }
        return Array(d[0..<i])
    }

    private func smError(_ m: String) -> L2PlusError { L2PlusError(.SECURE_MESSAGING_ERROR, m) }
}

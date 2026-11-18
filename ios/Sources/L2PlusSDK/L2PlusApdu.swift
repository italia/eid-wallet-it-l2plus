//
//  L2PlusApdu.swift
//  APDU and BER-TLV helpers.
//

import Foundation

struct L2PlusResponse {
    let data: [UInt8]
    let sw: UInt16
    var isSuccess: Bool { sw == 0x9000 }

    static func parse(_ raw: [UInt8]) throws -> L2PlusResponse {
        guard raw.count >= 2 else { throw L2PlusError(.TAG_LOST, "Response APDU too short") }
        return L2PlusResponse(data: Array(raw[0..<(raw.count - 2)]),
                              sw: UInt16(raw[raw.count - 2]) << 8 | UInt16(raw[raw.count - 1]))
    }
}

enum L2PlusApdu {
    /// Short APDU. `le`: nil = absent, 0 = 256 bytes.
    static func command(_ cla: UInt8, _ ins: UInt8, _ p1: UInt8, _ p2: UInt8, data: [UInt8] = [], le: Int? = nil) -> [UInt8] {
        precondition(data.count <= 255)
        var out: [UInt8] = [cla, ins, p1, p2]
        if !data.isEmpty { out.append(UInt8(data.count)); out += data }
        if let le = le { out.append(UInt8(le & 0xFF)) }
        return out
    }
}

func l2pHex(_ s: String) -> [UInt8] {
    let clean = s.replacingOccurrences(of: " ", with: "")
    var out: [UInt8] = []
    var i = clean.startIndex
    while i < clean.endIndex {
        let j = clean.index(i, offsetBy: 2)
        out.append(UInt8(clean[i..<j], radix: 16)!)
        i = j
    }
    return out
}

func l2pHexString(_ b: [UInt8]) -> String { b.map { String(format: "%02X", $0) }.joined() }

func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var r: UInt8 = 0
    for i in a.indices { r |= a[i] ^ b[i] }
    return r == 0
}

/// Tags up to 2 bytes, lengths up to 3 bytes.
enum L2PlusTlv {
    struct Header { let headerLength: Int; let valueLength: Int; var totalLength: Int { headerLength + valueLength } }

    struct Node { let tag: UInt8; let value: [UInt8]; let full: [UInt8] }

    enum Failure: Error { case malformed }

    static func header(_ b: [UInt8], at offset: Int = 0) throws -> Header {
        var pos = offset
        guard pos + 1 < b.count else { throw Failure.malformed }
        let first = b[pos]; pos += 1
        if first & 0x1F == 0x1F {
            repeat { guard pos < b.count else { throw Failure.malformed }; pos += 1 } while b[pos - 1] & 0x80 != 0
        }
        guard pos < b.count else { throw Failure.malformed }
        let l0 = Int(b[pos]); pos += 1
        var length = 0
        if l0 < 0x80 {
            length = l0
        } else if (0x81...0x83).contains(l0) {
            let n = l0 & 0x7F
            guard pos + n <= b.count else { throw Failure.malformed }
            for _ in 0..<n { length = length << 8 | Int(b[pos]); pos += 1 }
        } else {
            throw Failure.malformed
        }
        return Header(headerLength: pos - offset, valueLength: length)
    }

    /// Children of a constructed object with a single-byte tag.
    static func children(_ der: [UInt8], expectTag: UInt8) throws -> [Node] {
        let h = try header(der)
        guard der.first == expectTag, h.totalLength <= der.count else { throw Failure.malformed }
        var out: [Node] = []
        var pos = h.headerLength
        while pos < h.totalLength {
            let c = try header(der, at: pos)
            guard pos + c.totalLength <= h.totalLength else { throw Failure.malformed }
            out.append(Node(tag: der[pos],
                            value: Array(der[(pos + c.headerLength)..<(pos + c.totalLength)]),
                            full: Array(der[pos..<(pos + c.totalLength)])))
            pos += c.totalLength
        }
        return out
    }

    static func encode(_ tag: UInt16, _ value: [UInt8]) -> [UInt8] {
        var out: [UInt8] = tag > 0xFF ? [UInt8(tag >> 8), UInt8(tag & 0xFF)] : [UInt8(tag)]
        switch value.count {
        case ..<0x80: out.append(UInt8(value.count))
        case ...0xFF: out += [0x81, UInt8(value.count)]
        default: out += [0x82, UInt8(value.count >> 8), UInt8(value.count & 0xFF)]
        }
        return out + value
    }
}

//
//  L2PlusCardIO.swift
//  Plain and protected commands, and file reads.
//

import Foundation

/// Raw APDU channel to the card. Replaced by a fake in tests.
protocol L2PlusTransport: AnyObject {
    func transceive(_ apdu: [UInt8]) async throws -> [UInt8]
}

final class L2PlusCardIO {
    static let maxFileSize = 0x7FFF
    static let maxSmChunk = 0xDF
    static let iasChunk = 0x80

    private let transport: L2PlusTransport
    private let isCancelled: () -> Bool
    var sm: L2PlusSecureMessaging?

    init(transport: L2PlusTransport, isCancelled: @escaping () -> Bool) {
        self.transport = transport
        self.isCancelled = isCancelled
    }

    /// Plain command. Responses split with 61xx are collected with GET RESPONSE.
    func plain(_ command: [UInt8]) async throws -> L2PlusResponse {
        var r = try await send(command)
        guard r.sw >> 8 == 0x61 else { return r }
        var data = r.data
        var guardCount = 0
        while r.sw >> 8 == 0x61 {
            guardCount += 1
            if guardCount > 64 { throw L2PlusError(.INTERNAL_ERROR, "Too many GET RESPONSE") }
            r = try await send(L2PlusApdu.command(0x00, 0xC0, 0x00, 0x00, le: Int(r.sw & 0xFF)))
            data += r.data
        }
        return L2PlusResponse(data: data, sw: r.sw)
    }

    func secure(_ command: [UInt8]) async throws -> L2PlusResponse {
        guard let channel = sm else { throw L2PlusError(.INTERNAL_ERROR, "Secure messaging not established") }
        return try channel.unwrap(try await send(try channel.wrap(command)))
    }

    @discardableResult
    func expectOk(_ r: L2PlusResponse, _ code: L2PlusErrorCode, _ step: String) throws -> L2PlusResponse {
        guard r.isSuccess else { throw L2PlusError(code, "\(step): SW \(String(format: "%04X", r.sw))", sw: r.sw) }
        return r
    }

    /// Reads a whole TLV file: the length comes from the TLV header found in the first block.
    /// With `sfi` the file is selected by the first READ BINARY.
    func readTlvFile(_ code: L2PlusErrorCode, secure: Bool, sfi: UInt8? = nil) async throws -> [UInt8] {
        func exchange(_ c: [UInt8]) async throws -> L2PlusResponse {
            secure ? try await self.secure(c) : try await plain(c)
        }
        let first = try await exchange(L2PlusApdu.command(0x00, 0xB0, sfi.map { 0x80 | $0 } ?? 0x00, 0x00, le: 8))
        guard (first.isSuccess || first.sw == 0x6282), first.data.count >= 2 else {
            throw L2PlusError(code, "Cannot read file header", sw: first.sw)
        }
        let header: L2PlusTlv.Header
        do { header = try L2PlusTlv.header(first.data) } catch {
            throw L2PlusError(code, "Invalid file header")
        }
        let total = header.totalLength
        guard total <= Self.maxFileSize else { throw L2PlusError(code, "File too large") }
        var out = Array(first.data.prefix(total))
        while out.count < total {
            let offset = out.count
            let le = min(Self.maxSmChunk, total - offset)
            let r = try await exchange(L2PlusApdu.command(0x00, 0xB0, UInt8((offset >> 8) & 0x7F), UInt8(offset & 0xFF), le: le))
            guard r.isSuccess || r.sw == 0x6282 else { throw L2PlusError(code, "File read interrupted", sw: r.sw) }
            guard !r.data.isEmpty else { throw L2PlusError(code, "File shorter than its header") }
            out += r.data.prefix(total - offset)
            if r.sw == 0x6282 && out.count < total { throw L2PlusError(code, "File shorter than its header", sw: r.sw) }
        }
        return out
    }

    /// Plain read of an IAS file by FID, in 128-byte blocks.
    /// 6Cxx: repeat with the given Le. 6282: end of file. 6B00: offset past the end.
    func readIasFile(_ fid: UInt16, _ code: L2PlusErrorCode) async throws -> [UInt8] {
        let select = try await plain(L2PlusApdu.command(0x00, 0xA4, 0x02, 0x04, data: [UInt8(fid >> 8), UInt8(fid & 0xFF)]))
        guard select.isSuccess else {
            throw L2PlusError(code, String(format: "Cannot select file %04X", fid), sw: select.sw)
        }
        var out: [UInt8] = []
        while true {
            let offset = out.count
            guard offset <= Self.maxFileSize else { throw L2PlusError(code, "File too large") }
            func read(_ le: Int) async throws -> L2PlusResponse {
                try await plain(L2PlusApdu.command(0x00, 0xB0, UInt8((offset >> 8) & 0x7F), UInt8(offset & 0xFF), le: le))
            }
            var r = try await read(Self.iasChunk)
            if r.sw >> 8 == 0x6C { r = try await read(Int(r.sw & 0xFF)) }
            if r.isSuccess {
                if r.data.isEmpty { break }
                out += r.data
            } else if r.sw == 0x6282 {
                out += r.data
                break
            } else if r.sw == 0x6B00 && offset > 0 {
                break
            } else {
                throw L2PlusError(code, String(format: "Cannot read file %04X", fid), sw: r.sw)
            }
        }
        guard !out.isEmpty else { throw L2PlusError(code, String(format: "File %04X is empty", fid)) }
        return out
    }

    /// DER object at the start of `raw`. Trailing 0x00/0xFF padding is dropped, anything else is an error.
    static func derObject(_ raw: [UInt8], _ code: L2PlusErrorCode) throws -> [UInt8] {
        let h: L2PlusTlv.Header
        do { h = try L2PlusTlv.header(raw) } catch { throw L2PlusError(code, "Invalid DER content") }
        guard h.totalLength <= raw.count else { throw L2PlusError(code, "Truncated DER content") }
        for b in raw[h.totalLength...] where b != 0x00 && b != 0xFF {
            throw L2PlusError(code, "Unexpected data after DER object")
        }
        return Array(raw[0..<h.totalLength])
    }

    private func send(_ command: [UInt8]) async throws -> L2PlusResponse {
        if isCancelled() { throw L2PlusError(.CANCELLED, "Read cancelled") }
        return try L2PlusResponse.parse(try await transport.transceive(command))
    }
}

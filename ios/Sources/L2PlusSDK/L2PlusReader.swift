//
//  L2PlusReader.swift
//  Whole read in a single card session:
//  PACE, DG1/DG11/SOD, IAS key/SOD/challenge signature, then the local checks.
//

import Foundation

final class L2PlusReader {
    private static let emrtdAid = l2pHex("A0000002471001")
    private static let sfiDg1: UInt8 = 0x01
    private static let sfiDg11: UInt8 = 0x0B
    private static let sfiSod: UInt8 = 0x1D

    private let trust: L2PlusTrustConfig

    init(trust: L2PlusTrustConfig) { self.trust = trust }

    func read(transport: L2PlusTransport, request: L2PlusRequest,
              isCancelled: @escaping () -> Bool, onStep: @escaping (L2PlusStep) -> Void) async throws -> L2PlusResult {
        let card = L2PlusCardIO(transport: transport, isCancelled: isCancelled)
        defer { card.sm?.destroy(); card.sm = nil }

        onStep(.pace)
        card.sm = try await L2PlusPace.establish(card, access: request.access)
        try card.expectOk(try await card.secure(L2PlusApdu.command(0x00, 0xA4, 0x04, 0x0C, data: Self.emrtdAid)),
                          .MRTD_READ_FAILED, "Select eMRTD application")

        onStep(.readingMrtd)
        let dg1 = try await card.readTlvFile(.MRTD_READ_FAILED, secure: true, sfi: Self.sfiDg1)
        let dg11 = try await card.readTlvFile(.MRTD_READ_FAILED, secure: true, sfi: Self.sfiDg11)
        let sodMrtd = try await card.readTlvFile(.MRTD_READ_FAILED, secure: true, sfi: Self.sfiSod)
        guard dg1[0] == 0x61, dg11[0] == 0x6B, sodMrtd[0] == 0x77 else {
            throw L2PlusError(.MRTD_READ_FAILED, "Unexpected MRTD file tags")
        }

        onStep(.readingIas)
        let ias = try await L2PlusIas.read(card, challenge: request.challenge) { onStep(.signingChallenge) }

        onStep(.verifying)
        try verifyMrtd(dg1: dg1, dg11: dg11, sod: sodMrtd)
        try verifyIas(ias)

        return L2PlusResult(
            mrtd: .init(dg1: b64(dg1), dg11: b64(dg11), sod_mrtd: b64(sodMrtd)),
            ias: .init(ias_pk: b64(ias.publicKey), sod_ias: b64(ias.sod), challenge_signed: b64(ias.signedChallenge)))
    }

    private func verifyMrtd(dg1: [UInt8], dg11: [UInt8], sod: [UInt8]) throws {
        let signed = try L2PlusSodVerifier.verify(sod, anchors: trust.mrtdTrustAnchors, crls: trust.crls, invalid: .SOD_MRTD_INVALID)
        for (number, content) in [(1, dg1), (11, dg11)] {
            guard let expected = signed.hashes[number] else {
                throw L2PlusError(.DG_HASH_MISMATCH, "DG\(number) hash missing from SOD")
            }
            guard constantTimeEqual(expected, signed.digest(content)) else {
                throw L2PlusError(.DG_HASH_MISMATCH, "DG\(number) hash mismatch")
            }
        }
    }

    /// The IAS SOD must be valid and must contain the hash of the public key read from EF 1005,
    /// computed over either the DER object or the raw file content.
    private func verifyIas(_ ias: L2PlusIas.Evidence) throws {
        let signed = try L2PlusSodVerifier.verify(ias.sod, anchors: trust.iasTrustAnchors, crls: trust.crls, invalid: .SOD_IAS_INVALID)
        let candidates = [ias.publicKey, ias.publicKeyRaw].map(signed.digest)
        let bound = signed.hashes.values.contains { h in candidates.contains { constantTimeEqual($0, h) } }
        guard bound else { throw L2PlusError(.IAS_KEY_NOT_BOUND, "IAS public key not covered by the IAS SOD") }
    }

    private func b64(_ b: [UInt8]) -> String { Data(b).base64EncodedString() }
}

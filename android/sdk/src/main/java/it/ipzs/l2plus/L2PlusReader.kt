package it.ipzs.l2plus

import java.security.MessageDigest
import java.util.Base64

/**
 * Whole read in a single card session:
 * PACE, DG1/DG11/SOD, IAS key/SOD/challenge signature, then the local checks.
 */
internal class L2PlusReader(private val trust: L2PlusTrustConfig) {

    fun read(
        transport: ApduTransport,
        request: L2PlusRequest,
        isCancelled: () -> Boolean = { false },
        onStep: (L2PlusStep) -> Unit = {},
    ): L2PlusResult {
        val card = CardIo(transport, isCancelled)
        try {
            onStep(L2PlusStep.PACE)
            val sm = Pace.establish(card, request.access)
            card.sm = sm
            card.expectOk(
                card.secure(Apdu.command(0x00, 0xA4, 0x04, 0x0C, EMRTD_AID)),
                L2PlusErrorCode.MRTD_READ_FAILED, "Select eMRTD application",
            )

            onStep(L2PlusStep.READING_MRTD)
            val dg1 = card.readSelectedFile(L2PlusErrorCode.MRTD_READ_FAILED, sm, SFI_DG1)
            val dg11 = card.readSelectedFile(L2PlusErrorCode.MRTD_READ_FAILED, sm, SFI_DG11)
            val sodMrtd = card.readSelectedFile(L2PlusErrorCode.MRTD_READ_FAILED, sm, SFI_SOD)
            if (dg1[0] != 0x61.toByte() || dg11[0] != 0x6B.toByte() || sodMrtd[0] != 0x77.toByte()) {
                throw L2PlusException(L2PlusErrorCode.MRTD_READ_FAILED, "Unexpected MRTD file tags")
            }

            onStep(L2PlusStep.READING_IAS)
            val ias = Ias.read(card, request.challenge) { onStep(L2PlusStep.SIGNING_CHALLENGE) }

            onStep(L2PlusStep.VERIFYING)
            verifyMrtd(dg1, dg11, sodMrtd)
            verifyIas(ias)

            return L2PlusResult(
                mrtd = L2PlusResult.Mrtd(
                    dg1 = b64(dg1),
                    dg11 = b64(dg11),
                    sod_mrtd = b64(sodMrtd),
                ),
                ias = L2PlusResult.Ias(
                    ias_pk = b64(ias.publicKey),
                    sod_ias = b64(ias.sod),
                    challenge_signed = b64(ias.signedChallenge),
                ),
            )
        } finally {
            card.sm?.destroy()
            card.sm = null
        }
    }

    private fun verifyMrtd(dg1: ByteArray, dg11: ByteArray, sod: ByteArray) {
        val signed = SodVerifier.verify(sod, trust.mrtdTrustAnchors, trust.crls, L2PlusErrorCode.SOD_MRTD_INVALID)
        for ((number, content) in listOf(1 to dg1, 11 to dg11)) {
            val expected = signed.hashes[number]
                ?: throw L2PlusException(L2PlusErrorCode.DG_HASH_MISMATCH, "DG$number hash missing from SOD")
            if (!MessageDigest.isEqual(expected, SodVerifier.digest(signed.digestAlgorithm, content))) {
                throw L2PlusException(L2PlusErrorCode.DG_HASH_MISMATCH, "DG$number hash mismatch")
            }
        }
    }

    /**
     * The IAS SOD must be valid and must contain the hash of the public key read from EF 1005.
     * The hash is accepted over either the DER object or the raw file content.
     */
    private fun verifyIas(ias: Ias.Evidence) {
        val signed = SodVerifier.verify(ias.sod, trust.iasTrustAnchors, trust.crls, L2PlusErrorCode.SOD_IAS_INVALID)
        val candidates = listOf(ias.publicKey, ias.publicKeyRaw).map { SodVerifier.digest(signed.digestAlgorithm, it) }
        val bound = signed.hashes.values.any { h -> candidates.any { MessageDigest.isEqual(it, h) } }
        if (!bound) throw L2PlusException(L2PlusErrorCode.IAS_KEY_NOT_BOUND, "IAS public key not covered by the IAS SOD")
    }

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    companion object {
        private val EMRTD_AID = hexToBytes("A0000002471001")
        private const val SFI_DG1 = 0x01
        private const val SFI_DG11 = 0x0B
        private const val SFI_SOD = 0x1D
    }
}

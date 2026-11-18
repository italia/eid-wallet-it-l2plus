package it.ipzs.l2plus

/**
 * IAS application of the CIE: anti-cloning public key (EF 1005), IAS SOD (EF 1006) and
 * Internal Authentication of the challenge. All commands are sent in clear; no PIN is involved.
 */
internal object Ias {

    enum class Vendor { NXP, GEMALTO, ST }

    class Evidence(val publicKeyRaw: ByteArray, val publicKey: ByteArray, val sodRaw: ByteArray, val sod: ByteArray, val signedChallenge: ByteArray)

    private val IAS_AID = hexToBytes("A0000000308000000009816001")
    private val CIE_AID = hexToBytes("A00000000039")
    private const val EF_ATR = 0x2F01
    private const val EF_INT_KPUB = 0x1005
    private const val EF_SOD_IAS = 0x1006
    private const val INT_AUTH_KEY_ID: Byte = 0x83.toByte()

    // Byte sequences that identify the chip manufacturer in EF.ATR.
    private val NXP_ATR = hexToBytes("80 00 43 01 B8 46 04 10 10 10 10 47 03 94")
    private val GEMALTO_ATR = hexToBytes("49 61 73 45 63 63 52 6F 6F 74") // "IasEccRoot"
    private val GEMALTO2_ATR = hexToBytes("47 03 94 41 C0")
    private val ST_ATR = hexToBytes(
        "80 00 43 01 B9 46 04 00 00 00 10 47 03 94 01 81 4F 0C A0 00 00 00 95 00 00 00 00 8A 00 01 " +
            "E0 10 02 02 00 FF 02 02 00 FF 02 02 01 00 02 02 01 00 78 08 06 06 2B 81 22 F8 78 02 82 02 90 00",
    )

    fun read(card: CardIo, challenge: ByteArray, onSigning: () -> Unit): Evidence {
        // Leave the eMRTD secure messaging session and go back to the MF.
        card.sm?.destroy()
        card.sm = null
        card.expectOk(
            card.plain(Apdu.command(0x00, 0xA4, 0x00, 0x00, byteArrayOf(0x3F, 0x00))),
            L2PlusErrorCode.IAS_READ_FAILED, "Select MF",
        )
        val vendor = detectVendor(card)

        selectIas(card, vendor)
        card.expectOk(
            card.plain(Apdu.command(0x00, 0xA4, 0x04, 0x0C, CIE_AID)),
            L2PlusErrorCode.IAS_READ_FAILED, "Select DF CIE",
        )

        val keyRaw = card.readIasFile(EF_INT_KPUB, L2PlusErrorCode.IAS_READ_FAILED)
        val key = CardIo.derObject(keyRaw, L2PlusErrorCode.IAS_READ_FAILED)
        val sodRaw = card.readIasFile(EF_SOD_IAS, L2PlusErrorCode.IAS_READ_FAILED)
        val sod = CardIo.derObject(sodRaw, L2PlusErrorCode.IAS_READ_FAILED)

        onSigning()
        // MSE:Set: algorithm 80 01 02, key reference 84 01 83.
        card.expectOk(
            card.plain(Apdu.command(0x00, 0x22, 0x41, 0xA4, byteArrayOf(0x80.toByte(), 0x01, 0x02, 0x84.toByte(), 0x01, INT_AUTH_KEY_ID))),
            L2PlusErrorCode.IAS_SIGN_FAILED, "MSE:Set Internal Authentication",
        )
        // INTERNAL AUTHENTICATE without Le: the card answers with 61xx.
        val signed = card.expectOk(
            card.plain(Apdu.command(0x00, 0x88, 0x00, 0x00, challenge)),
            L2PlusErrorCode.IAS_SIGN_FAILED, "Internal Authenticate",
        ).data
        if (signed.isEmpty()) throw L2PlusException(L2PlusErrorCode.IAS_SIGN_FAILED, "Empty signature")
        return Evidence(keyRaw, key, sodRaw, sod, signed)
    }

    private fun detectVendor(card: CardIo): Vendor {
        val atr = card.readIasFile(EF_ATR, L2PlusErrorCode.CIE_TYPE_UNKNOWN)
        return vendorFromAtr(atr)
            ?: throw L2PlusException(L2PlusErrorCode.CIE_TYPE_UNKNOWN, "Unknown CIE manufacturer")
    }

    fun vendorFromAtr(atr: ByteArray): Vendor? = when {
        atr.containsSequence(NXP_ATR) -> Vendor.NXP
        atr.containsSequence(GEMALTO_ATR) -> Vendor.GEMALTO
        atr.containsSequence(GEMALTO2_ATR) -> Vendor.GEMALTO
        atr.containsSequence(ST_ATR) -> Vendor.ST
        else -> null
    }

    /** NXP chips expose IAS at the MF, the others by AID. */
    private fun selectIas(card: CardIo, vendor: Vendor) {
        val command = when (vendor) {
            Vendor.NXP -> Apdu.command(0x00, 0xA4, 0x00, 0x00)
            Vendor.GEMALTO, Vendor.ST -> Apdu.command(0x00, 0xA4, 0x04, 0x0C, IAS_AID)
        }
        card.expectOk(card.plain(command), L2PlusErrorCode.IAS_READ_FAILED, "Select IAS application")
    }

    private fun ByteArray.containsSequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > size) return false
        outer@ for (i in 0..size - needle.size) {
            for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }
}

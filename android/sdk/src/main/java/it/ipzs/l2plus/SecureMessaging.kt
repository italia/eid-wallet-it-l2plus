package it.ipzs.l2plus

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Secure messaging (ICAO 9303-11 §9.8). One instance per PACE session.
 * A protected response is accepted only with DO'99' and a valid DO'8E'.
 */
internal class SecureMessaging(
    private val cipher: PaceCipher,
    kEnc: ByteArray,
    kMac: ByteArray,
    initialSsc: ByteArray,
) {
    private val kEnc = kEnc.copyOf()
    private val kMac = kMac.copyOf()
    private val ssc = initialSsc.copyOf()
    private val blockSize = cipher.blockSize

    init {
        require(ssc.size == blockSize) { "Wrong SSC length" }
    }

    /** Protects a short plain APDU. */
    fun wrap(command: ByteArray): ByteArray {
        require(command.size >= 4)
        val cla = (command[0].toInt() and 0xFF) or 0x0C
        val ins = command[1].toInt() and 0xFF
        val header = byteArrayOf(cla.toByte(), command[1], command[2], command[3])

        var data: ByteArray? = null
        var le: Int? = null
        when {
            command.size == 4 -> Unit
            command.size == 5 -> le = command[4].toInt() and 0xFF
            else -> {
                val lc = command[4].toInt() and 0xFF
                require(command.size == 5 + lc || command.size == 6 + lc) { "Malformed APDU" }
                data = command.copyOfRange(5, 5 + lc)
                if (command.size == 6 + lc) le = command[5 + lc].toInt() and 0xFF
            }
        }

        increment()
        val body = ByteArrayOutputStream()
        if (data != null && data.isNotEmpty()) {
            val enc = cipher.encrypt(kEnc, isoPad(data, blockSize), cipher.smIv(kEnc, ssc))
            // Odd INS uses DO'85' (no padding indicator), even INS uses DO'87'.
            body.write(if (ins % 2 == 0) Tlv.encode(0x87, byteArrayOf(0x01) + enc) else Tlv.encode(0x85, enc))
        }
        if (le != null) {
            body.write(byteArrayOf(0x97.toByte(), 0x01, le.toByte()))
        }
        val dos = body.toByteArray()
        val mac = cipher.mac(kMac, isoPad(ssc + isoPad(header, blockSize) + dos, blockSize))
        val protectedData = dos + byteArrayOf(0x8E.toByte(), 0x08) + mac
        require(protectedData.size <= 255) { "Protected APDU too long for a short APDU" }
        return header + byteArrayOf(protectedData.size.toByte()) + protectedData + byteArrayOf(0x00)
    }

    /**
     * Checks and decrypts a protected response.
     * @return plain data (possibly empty) and the status word found in DO'99'.
     */
    fun unwrap(response: ResponseApdu): ResponseApdu {
        increment()
        if (!response.isSuccess && response.data.isEmpty()) {
            // Plain error: the card has closed the session, no data is accepted.
            return ResponseApdu(ByteArray(0), response.sw)
        }
        val raw = response.data
        var pos = 0
        var do87: ByteArray? = null
        var do99: ByteArray? = null
        var do8e: ByteArray? = null
        val macData = ByteArrayOutputStream()
        try {
            while (pos < raw.size) {
                val tag = raw[pos].toInt() and 0xFF
                val h = Tlv.header(raw, pos)
                if (pos + h.totalLength > raw.size) smError("Truncated data object")
                val full = raw.copyOfRange(pos, pos + h.totalLength)
                val value = raw.copyOfRange(pos + h.headerLength, pos + h.totalLength)
                when (tag) {
                    0x87, 0x85 -> { if (do87 != null || do99 != null) smError("Duplicate data object"); do87 = full; macData.write(full) }
                    0x99 -> { if (do99 != null) smError("Duplicate data object"); do99 = value; macData.write(full) }
                    0x8E -> { do8e = value; if (pos + h.totalLength != raw.size) smError("Data after MAC") }
                    else -> smError("Unexpected data object")
                }
                pos += h.totalLength
            }
        } catch (e: IllegalArgumentException) {
            smError("Invalid secure messaging structure")
        }
        val mac = do8e ?: smError("Missing MAC")
        val sw = do99 ?: smError("Missing protected status word")
        if (sw.size != 2) smError("Wrong DO'99' length")
        val expected = cipher.mac(kMac, isoPad(ssc + macData.toByteArray(), blockSize))
        if (mac.size != 8 || !MessageDigest.isEqual(expected, mac)) smError("Invalid MAC")
        val protectedSw = ((sw[0].toInt() and 0xFF) shl 8) or (sw[1].toInt() and 0xFF)

        var plain = ByteArray(0)
        do87?.let { obj ->
            val h = Tlv.header(obj)
            var value = obj.copyOfRange(h.headerLength, obj.size)
            if ((obj[0].toInt() and 0xFF) == 0x87) {
                if (value.isEmpty() || value[0].toInt() != 0x01) smError("Invalid padding indicator")
                value = value.copyOfRange(1, value.size)
            }
            if (value.isEmpty() || value.size % blockSize != 0) smError("Invalid cryptogram length")
            plain = unpad(cipher.decrypt(kEnc, value, cipher.smIv(kEnc, ssc)))
        }
        return ResponseApdu(plain, protectedSw)
    }

    /** Wipes the session keys. */
    fun destroy() {
        kEnc.fill(0); kMac.fill(0); ssc.fill(0)
    }

    private fun increment() {
        for (i in ssc.indices.reversed()) {
            val v = (ssc[i].toInt() and 0xFF) + 1
            ssc[i] = v.toByte()
            if (v <= 0xFF) return
        }
    }

    private fun unpad(data: ByteArray): ByteArray {
        var i = data.size - 1
        while (i >= 0 && data[i].toInt() == 0) i--
        if (i < 0 || (data[i].toInt() and 0xFF) != 0x80) smError("Invalid padding")
        return data.copyOfRange(0, i)
    }

    private fun smError(message: String): Nothing =
        throw L2PlusException(L2PlusErrorCode.SECURE_MESSAGING_ERROR, message)
}

package it.ipzs.l2plus

import java.io.ByteArrayOutputStream

/** Raw APDU channel to the card. Replaced by a fake in unit tests. */
interface ApduTransport {
    /** Sends a command and returns the full response, status word included. */
    fun transceive(command: ByteArray): ByteArray
}

class ResponseApdu(val data: ByteArray, val sw: Int) {
    val isSuccess: Boolean get() = sw == SW_OK

    companion object {
        const val SW_OK = 0x9000

        fun parse(raw: ByteArray): ResponseApdu {
            if (raw.size < 2) {
                throw L2PlusException(L2PlusErrorCode.TAG_LOST, "Response APDU too short")
            }
            val sw = ((raw[raw.size - 2].toInt() and 0xFF) shl 8) or (raw[raw.size - 1].toInt() and 0xFF)
            return ResponseApdu(raw.copyOfRange(0, raw.size - 2), sw)
        }
    }
}

/** Short APDUs (ISO 7816-4). */
internal object Apdu {

    /** @param le expected length: null = absent, 0 = 256 bytes. */
    fun command(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray? = null, le: Int? = null): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(cla); out.write(ins); out.write(p1); out.write(p2)
        if (data != null && data.isNotEmpty()) {
            require(data.size <= 255) { "Lc too long for a short APDU" }
            out.write(data.size)
            out.write(data)
        }
        if (le != null) {
            require(le in 0..256) { "Invalid Le" }
            out.write(le and 0xFF)
        }
        return out.toByteArray()
    }
}

internal fun ByteArray.hex(): String = joinToString("") { "%02X".format(it) }

internal fun hexToBytes(hex: String): ByteArray {
    val clean = hex.replace(" ", "")
    require(clean.length % 2 == 0)
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

/** BER-TLV helpers: tags up to 2 bytes, lengths up to 3 bytes. */
internal object Tlv {

    class Header(val tagLength: Int, val lengthLength: Int, val valueLength: Int) {
        val headerLength: Int get() = tagLength + lengthLength
        val totalLength: Int get() = headerLength + valueLength
    }

    fun header(bytes: ByteArray, offset: Int = 0): Header {
        if (bytes.size <= offset + 1) throw IllegalArgumentException("Truncated TLV")
        var pos = offset
        val first = bytes[pos++].toInt() and 0xFF
        if (first and 0x1F == 0x1F) {
            while (true) {
                if (pos >= bytes.size) throw IllegalArgumentException("Truncated TLV")
                val b = bytes[pos++].toInt() and 0xFF
                if (b and 0x80 == 0) break
            }
        }
        val tagLength = pos - offset
        if (pos >= bytes.size) throw IllegalArgumentException("Truncated TLV")
        val l0 = bytes[pos++].toInt() and 0xFF
        val valueLength: Int
        val lengthLength: Int
        when {
            l0 < 0x80 -> { valueLength = l0; lengthLength = 1 }
            l0 in 0x81..0x83 -> {
                val n = l0 and 0x7F
                if (pos + n > bytes.size) throw IllegalArgumentException("Truncated TLV")
                var v = 0
                repeat(n) { v = (v shl 8) or (bytes[pos++].toInt() and 0xFF) }
                valueLength = v
                lengthLength = 1 + n
            }
            else -> throw IllegalArgumentException("Unsupported TLV length")
        }
        return Header(tagLength, lengthLength, valueLength)
    }

    fun encode(tag: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        if (tag > 0xFF) out.write(tag shr 8)
        out.write(tag and 0xFF)
        when {
            value.size < 0x80 -> out.write(value.size)
            value.size <= 0xFF -> { out.write(0x81); out.write(value.size) }
            else -> { out.write(0x82); out.write(value.size shr 8); out.write(value.size and 0xFF) }
        }
        out.write(value)
        return out.toByteArray()
    }
}

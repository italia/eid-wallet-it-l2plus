package it.ipzs.l2plus

import java.io.ByteArrayOutputStream

/** Plain and protected commands, and file reads. */
internal class CardIo(
    private val transport: ApduTransport,
    private val isCancelled: () -> Boolean,
) {
    var sm: SecureMessaging? = null

    /** Plain command. Responses split with 61xx are collected with GET RESPONSE. */
    fun plain(command: ByteArray): ResponseApdu {
        var r = send(command)
        if ((r.sw shr 8) != 0x61) return r
        val out = ByteArrayOutputStream()
        out.write(r.data)
        var guard = 0
        while ((r.sw shr 8) == 0x61) {
            if (++guard > 64) throw L2PlusException(L2PlusErrorCode.INTERNAL_ERROR, "Too many GET RESPONSE")
            r = send(Apdu.command(0x00, 0xC0, 0x00, 0x00, le = r.sw and 0xFF))
            out.write(r.data)
        }
        return ResponseApdu(out.toByteArray(), r.sw)
    }

    fun secure(command: ByteArray): ResponseApdu {
        val channel = sm ?: throw L2PlusException(L2PlusErrorCode.INTERNAL_ERROR, "Secure messaging not established")
        return channel.unwrap(send(channel.wrap(command)))
    }

    fun expectOk(r: ResponseApdu, code: L2PlusErrorCode, step: String): ResponseApdu {
        if (!r.isSuccess) throw L2PlusException(code, "$step: SW ${"%04X".format(r.sw)}", r.sw)
        return r
    }

    /**
     * Reads a whole TLV file: the length comes from the TLV header found in the first block.
     * With [sfi] the file is selected by the first READ BINARY.
     */
    fun readSelectedFile(errorCode: L2PlusErrorCode, secure: SecureMessaging?, sfi: Int? = null): ByteArray {
        val exchange: (ByteArray) -> ResponseApdu = if (secure != null) { c -> this.secure(c) } else { c -> plain(c) }
        val firstP1 = if (sfi != null) 0x80 or sfi else 0x00
        val first = exchange(Apdu.command(0x00, 0xB0, firstP1, 0x00, le = 8))
        if (!(first.isSuccess || first.sw == 0x6282) || first.data.size < 2) {
            throw L2PlusException(errorCode, "Cannot read file header", first.sw)
        }
        val header = try {
            Tlv.header(first.data)
        } catch (e: IllegalArgumentException) {
            throw L2PlusException(errorCode, "Invalid file header", cause = e)
        }
        val total = header.totalLength
        if (total > MAX_FILE_SIZE) throw L2PlusException(errorCode, "File too large")
        val out = ByteArrayOutputStream()
        out.write(first.data, 0, minOf(first.data.size, total))
        while (out.size() < total) {
            val offset = out.size()
            val le = minOf(MAX_SM_CHUNK, total - offset)
            val r = exchange(Apdu.command(0x00, 0xB0, (offset shr 8) and 0x7F, offset and 0xFF, le = le))
            if (!r.isSuccess && r.sw != 0x6282) {
                throw L2PlusException(errorCode, "File read interrupted", r.sw)
            }
            if (r.data.isEmpty()) throw L2PlusException(errorCode, "File shorter than its header")
            out.write(r.data, 0, minOf(r.data.size, total - offset))
            if (r.sw == 0x6282 && out.size() < total) {
                throw L2PlusException(errorCode, "File shorter than its header", r.sw)
            }
        }
        return out.toByteArray()
    }

    /**
     * Plain read of an IAS file by FID, in 128-byte blocks.
     * 6Cxx: repeat with the given Le. 6282: end of file. 6B00: offset past the end.
     * Returns the raw content, trailing padding included.
     */
    fun readIasFile(fid: Int, errorCode: L2PlusErrorCode): ByteArray {
        val select = plain(Apdu.command(0x00, 0xA4, 0x02, 0x04, byteArrayOf((fid shr 8).toByte(), fid.toByte())))
        if (!select.isSuccess) {
            throw L2PlusException(errorCode, "Cannot select file %04X".format(fid), select.sw)
        }
        val out = ByteArrayOutputStream()
        while (true) {
            val offset = out.size()
            if (offset > MAX_FILE_SIZE) throw L2PlusException(errorCode, "File too large")
            val read = { le: Int -> plain(Apdu.command(0x00, 0xB0, (offset shr 8) and 0x7F, offset and 0xFF, le = le)) }
            var r = read(IAS_CHUNK)
            if ((r.sw shr 8) == 0x6C) r = read(r.sw and 0xFF)
            when {
                r.isSuccess -> {
                    if (r.data.isEmpty()) break
                    out.write(r.data)
                }
                r.sw == 0x6282 -> { out.write(r.data); break }
                r.sw == 0x6B00 && offset > 0 -> break
                else -> throw L2PlusException(errorCode, "Cannot read file %04X".format(fid), r.sw)
            }
        }
        if (out.size() == 0) throw L2PlusException(errorCode, "File %04X is empty".format(fid))
        return out.toByteArray()
    }

    private fun send(command: ByteArray): ResponseApdu {
        if (isCancelled()) throw L2PlusException(L2PlusErrorCode.CANCELLED, "Read cancelled")
        return ResponseApdu.parse(transport.transceive(command))
    }

    companion object {
        /** READ BINARY with even INS addresses 15-bit offsets. */
        const val MAX_FILE_SIZE = 0x7FFF
        const val MAX_SM_CHUNK = 0xDF
        const val IAS_CHUNK = 0x80

        /** DER object at the start of [raw]. Trailing 0x00/0xFF padding is dropped, anything else is an error. */
        fun derObject(raw: ByteArray, errorCode: L2PlusErrorCode): ByteArray {
            val h = try {
                Tlv.header(raw)
            } catch (e: IllegalArgumentException) {
                throw L2PlusException(errorCode, "Invalid DER content", cause = e)
            }
            if (h.totalLength > raw.size) throw L2PlusException(errorCode, "Truncated DER content")
            for (i in h.totalLength until raw.size) {
                val b = raw[i].toInt() and 0xFF
                if (b != 0x00 && b != 0xFF) throw L2PlusException(errorCode, "Unexpected data after DER object")
            }
            return raw.copyOfRange(0, h.totalLength)
        }
    }
}

package it.ipzs.l2plus

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * PACE with Generic Mapping (ICAO 9303-11 §4.4), using the CAN or the MRZ data.
 * There is no BAC fallback: if PACE is missing or fails, the read stops.
 */
internal object Pace {

    private const val PWD_MRZ: Byte = 0x01
    private const val PWD_CAN: Byte = 0x02

    private val defaultRandom = SecureRandom()

    fun establish(card: CardIo, access: L2PlusRequest.ValidAccess, random: SecureRandom = defaultRandom): SecureMessaging {
        val info = readPaceInfo(card)
        val (password, pwdRef) = when (access) {
            is L2PlusRequest.ValidAccess.Mrz ->
                MessageDigest.getInstance("SHA-1").digest(access.mrzInformation.toByteArray(Charsets.US_ASCII)) to PWD_MRZ
            is L2PlusRequest.ValidAccess.Can ->
                access.can.toByteArray(Charsets.US_ASCII) to PWD_CAN
        }

        try {
            val mse = Tlv.encode(0x80, info.oidBytes) + Tlv.encode(0x83, byteArrayOf(pwdRef))
            card.expectOk(card.plain(Apdu.command(0x00, 0x22, 0xC1, 0xA4, mse)), L2PlusErrorCode.PACE_FAILED, "MSE:Set AT")

            // Step 1: encrypted nonce.
            val r1 = card.expectOk(card.plain(generalAuthenticate(true, ByteArray(0))), L2PlusErrorCode.PACE_FAILED, "General Authenticate 1")
            val nonce = decryptNonce(info.cipher, password, dynamicObject(r1.data, 0x80))

            // Step 2: mapping.
            val mapKey = info.group.generatePrivateKey(random)
            val r2 = card.expectOk(
                card.plain(generalAuthenticate(true, Tlv.encode(0x81, info.group.publicKey(mapKey)))),
                L2PlusErrorCode.PACE_FAILED, "General Authenticate 2",
            )
            val group = info.group.map(nonce, mapKey, dynamicObject(r2.data, 0x82))
            nonce.fill(0)

            // Step 3: key agreement on the mapped group.
            val ephKey = group.generatePrivateKey(random)
            val ephPublic = group.publicKey(ephKey)
            val r3 = card.expectOk(
                card.plain(generalAuthenticate(true, Tlv.encode(0x83, ephPublic))),
                L2PlusErrorCode.PACE_FAILED, "General Authenticate 3",
            )
            val cardEphPublic = dynamicObject(r3.data, 0x84)
            if (cardEphPublic.contentEquals(ephPublic)) {
                throw L2PlusException(L2PlusErrorCode.PACE_FAILED, "Invalid card ephemeral key")
            }
            val shared = group.sharedSecret(ephKey, cardEphPublic)
            val kEnc = info.cipher.kdf(shared, 1)
            val kMac = info.cipher.kdf(shared, 2)
            shared.fill(0)

            // Step 4: mutual authentication tokens.
            val token = info.cipher.authToken(kMac, authData(info, group, cardEphPublic))
            val r4 = card.expectOk(
                card.plain(generalAuthenticate(false, Tlv.encode(0x85, token))),
                L2PlusErrorCode.PACE_FAILED, "General Authenticate 4",
            )
            val expected = info.cipher.authToken(kMac, authData(info, group, ephPublic))
            if (!MessageDigest.isEqual(expected, dynamicObject(r4.data, 0x86))) {
                throw L2PlusException(L2PlusErrorCode.PACE_FAILED, "Invalid card authentication token")
            }

            val sm = SecureMessaging(info.cipher, kEnc, kMac, ByteArray(info.cipher.blockSize))
            kEnc.fill(0); kMac.fill(0)
            return sm
        } catch (e: L2PlusException) {
            throw e
        } catch (e: Exception) {
            throw L2PlusException(L2PlusErrorCode.PACE_FAILED, "PACE protocol error", cause = e)
        } finally {
            password.fill(0)
        }
    }

    fun decryptNonce(cipher: PaceCipher, password: ByteArray, encryptedNonce: ByteArray): ByteArray {
        val kPi = cipher.kdf(password, 3)
        try {
            return cipher.decrypt(kPi, encryptedNonce)
        } finally {
            kPi.fill(0)
        }
    }

    fun authData(info: PaceInfo, group: PaceGroup, publicKey: ByteArray): ByteArray =
        Tlv.encode(0x7F49, Tlv.encode(0x06, info.oidBytes) + group.tokenKeyObject(publicKey))

    /** EF.CardAccess (FID 011C), read in clear. */
    private fun readPaceInfo(card: CardIo): PaceInfo {
        val select = card.plain(Apdu.command(0x00, 0xA4, 0x02, 0x0C, byteArrayOf(0x01, 0x1C)))
        if (!select.isSuccess) {
            throw L2PlusException(L2PlusErrorCode.PACE_NOT_SUPPORTED, "EF.CardAccess not found", select.sw)
        }
        val content = card.readSelectedFile(L2PlusErrorCode.PACE_NOT_SUPPORTED, secure = null)
        val info = try {
            PaceInfo.select(content)
        } catch (e: Exception) {
            throw L2PlusException(L2PlusErrorCode.PACE_NOT_SUPPORTED, "Invalid EF.CardAccess", cause = e)
        }
        return info ?: throw L2PlusException(L2PlusErrorCode.PACE_NOT_SUPPORTED, "No supported PACEInfo")
    }

    private fun dynamicObject(response: ByteArray, tag: Int): ByteArray {
        val outer = Tlv.header(response)
        if ((response[0].toInt() and 0xFF) != 0x7C || outer.totalLength > response.size) {
            throw L2PlusException(L2PlusErrorCode.PACE_FAILED, "Invalid General Authenticate response")
        }
        val inner = response.copyOfRange(outer.headerLength, outer.totalLength)
        if (inner.isEmpty() || (inner[0].toInt() and 0xFF) != tag) {
            throw L2PlusException(L2PlusErrorCode.PACE_FAILED, "Invalid General Authenticate response")
        }
        val h = Tlv.header(inner)
        if (h.totalLength > inner.size) {
            throw L2PlusException(L2PlusErrorCode.PACE_FAILED, "Truncated General Authenticate response")
        }
        return inner.copyOfRange(h.headerLength, h.totalLength)
    }

    /** General Authenticate with dynamic authentication data (7C). Uses an extended APDU when needed. */
    private fun generalAuthenticate(chained: Boolean, dynamicData: ByteArray): ByteArray {
        val cla = if (chained) 0x10 else 0x00
        val data = Tlv.encode(0x7C, dynamicData)
        if (data.size <= 255) return Apdu.command(cla, 0x86, 0x00, 0x00, data, le = 0)
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(cla.toByte(), 0x86.toByte(), 0x00, 0x00, 0x00, (data.size shr 8).toByte(), data.size.toByte()))
        out.write(data)
        out.write(byteArrayOf(0x00, 0x00))
        return out.toByteArray()
    }
}

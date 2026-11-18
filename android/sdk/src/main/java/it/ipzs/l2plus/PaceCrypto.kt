package it.ipzs.l2plus

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.DESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Cipher suite selected by the last arc of the PACE OID (ICAO 9303-11 §9.2 and §9.8). */
internal enum class PaceCipher(val blockSize: Int, private val keyLength: Int, private val kdfHash: String) {
    DES3(8, 16, "SHA-1"),
    AES128(16, 16, "SHA-1"),
    AES192(16, 24, "SHA-256"),
    AES256(16, 32, "SHA-256");

    /** KDF(K, c) = H(K || c), truncated to the key length. c = 1 (enc), 2 (mac), 3 (password). */
    fun kdf(secret: ByteArray, counter: Int): ByteArray {
        val md = MessageDigest.getInstance(kdfHash)
        md.update(secret)
        md.update(byteArrayOf(0, 0, 0, counter.toByte()))
        return md.digest().copyOf(keyLength)
    }

    /** CBC without padding. */
    fun encrypt(key: ByteArray, data: ByteArray, iv: ByteArray = ByteArray(blockSize)): ByteArray =
        cbc(Cipher.ENCRYPT_MODE, key, data, iv)

    fun decrypt(key: ByteArray, data: ByteArray, iv: ByteArray = ByteArray(blockSize)): ByteArray =
        cbc(Cipher.DECRYPT_MODE, key, data, iv)

    /** Secure messaging IV: E(K_enc, SSC) for AES, zero for 3DES. */
    fun smIv(kEnc: ByteArray, ssc: ByteArray): ByteArray =
        if (this == DES3) ByteArray(8) else ecb(kEnc, ssc)

    /** 8-byte MAC: retail MAC for 3DES (input already padded), CMAC for AES. */
    fun mac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = if (this == DES3) ISO9797Alg3Mac(DESEngine()) else CMac(AESEngine.newInstance(), 64)
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out.copyOf(8)
    }

    /** PACE authentication token over the public key data object. */
    fun authToken(kMac: ByteArray, authData: ByteArray): ByteArray =
        mac(kMac, if (this == DES3) isoPad(authData, 8) else authData)

    private fun cbc(mode: Int, key: ByteArray, data: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(if (this == DES3) "DESede/CBC/NoPadding" else "AES/CBC/NoPadding")
        cipher.init(mode, secretKey(key), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    private fun ecb(key: ByteArray, block: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey(key))
        return cipher.doFinal(block)
    }

    private fun secretKey(key: ByteArray): SecretKeySpec =
        if (this == DES3) SecretKeySpec(key + key.copyOf(8), "DESede") else SecretKeySpec(key, "AES")

    companion object {
        fun fromOid(oid: String): PaceCipher? = when (oid.substringAfterLast('.')) {
            "1" -> DES3
            "2" -> AES128
            "3" -> AES192
            "4" -> AES256
            else -> null
        }
    }
}

/** ISO/IEC 9797-1 padding method 2. */
internal fun isoPad(data: ByteArray, blockSize: Int): ByteArray {
    val out = ByteArray(data.size + blockSize - data.size % blockSize)
    data.copyInto(out)
    out[data.size] = 0x80.toByte()
    return out
}

/** Group used for the key agreements of PACE Generic Mapping. */
internal sealed class PaceGroup {

    abstract fun generatePrivateKey(random: SecureRandom): BigInteger

    abstract fun publicKey(privateKey: BigInteger): ByteArray

    /** Shared secret used by the KDF: x coordinate for ECDH, Z for DH. */
    abstract fun sharedSecret(privateKey: BigInteger, peerPublicKey: ByteArray): ByteArray

    /** Generic Mapping: new generator s·G + H, where H is the result of the mapping key agreement. */
    abstract fun map(nonce: ByteArray, privateKey: BigInteger, peerPublicKey: ByteArray): PaceGroup

    /** Public key data object used inside the authentication token (tag 86 for ECDH, 84 for DH). */
    abstract fun tokenKeyObject(publicKey: ByteArray): ByteArray

    class Ec(private val curve: ECCurve, private val g: ECPoint, private val n: BigInteger) : PaceGroup() {
        private val fieldLength = (curve.fieldSize + 7) / 8

        override fun generatePrivateKey(random: SecureRandom): BigInteger = randomBelow(n, random)

        override fun publicKey(privateKey: BigInteger): ByteArray = g.multiply(privateKey).normalize().getEncoded(false)

        override fun sharedSecret(privateKey: BigInteger, peerPublicKey: ByteArray): ByteArray =
            unsigned(agree(privateKey, peerPublicKey).affineXCoord.toBigInteger(), fieldLength)

        override fun map(nonce: ByteArray, privateKey: BigInteger, peerPublicKey: ByteArray): PaceGroup {
            val h = agree(privateKey, peerPublicKey)
            val mapped = g.multiply(BigInteger(1, nonce)).add(h).normalize()
            require(!mapped.isInfinity) { "Invalid mapped generator" }
            return Ec(curve, mapped, n)
        }

        override fun tokenKeyObject(publicKey: ByteArray): ByteArray = Tlv.encode(0x86, publicKey)

        private fun agree(privateKey: BigInteger, peerPublicKey: ByteArray): ECPoint {
            val peer = curve.decodePoint(peerPublicKey)
            require(!peer.isInfinity && peer.isValid) { "Invalid peer public key" }
            val shared = peer.multiply(privateKey).normalize()
            require(!shared.isInfinity) { "Invalid shared point" }
            return shared
        }
    }

    class Dh(private val p: BigInteger, private val q: BigInteger, private val g: BigInteger) : PaceGroup() {
        private val length = (p.bitLength() + 7) / 8

        override fun generatePrivateKey(random: SecureRandom): BigInteger = randomBelow(q, random)

        override fun publicKey(privateKey: BigInteger): ByteArray = unsigned(g.modPow(privateKey, p), length)

        override fun sharedSecret(privateKey: BigInteger, peerPublicKey: ByteArray): ByteArray =
            unsigned(agree(privateKey, peerPublicKey), length)

        override fun map(nonce: ByteArray, privateKey: BigInteger, peerPublicKey: ByteArray): PaceGroup {
            val h = agree(privateKey, peerPublicKey)
            val mapped = g.modPow(BigInteger(1, nonce), p).multiply(h).mod(p)
            require(mapped > BigInteger.ONE) { "Invalid mapped generator" }
            return Dh(p, q, mapped)
        }

        override fun tokenKeyObject(publicKey: ByteArray): ByteArray = Tlv.encode(0x84, publicKey)

        private fun agree(privateKey: BigInteger, peerPublicKey: ByteArray): BigInteger {
            val y = BigInteger(1, peerPublicKey)
            require(y > BigInteger.ONE && y < p.subtract(BigInteger.ONE)) { "Invalid peer public key" }
            require(y.modPow(q, p) == BigInteger.ONE) { "Peer public key not in the subgroup" }
            return y.modPow(privateKey, p)
        }
    }


    /** RFC 5114 §2.1-2.3 (domain parameter IDs 0, 1 and 2). */
    private object Rfc5114 {
        val G1024_160 = Dh(
            BigInteger(
                "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61" +
                "6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF" +
                "ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0" +
                "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
                16,
            ),
            BigInteger(
                "F518AA8781A8DF278ABA4E7D64B7CB9D49462353",
                16,
            ),
            BigInteger(
                "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31" +
                "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4" +
                "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A" +
                "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
                16,
            ),
        )
        val G2048_224 = Dh(
            BigInteger(
                "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75" +
                "E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A6" +
                "6D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
                "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A3170918836" +
                "81286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A074" +
                "15987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
                "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29" +
                "E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F",
                16,
            ),
            BigInteger(
                "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB",
                16,
            ),
            BigInteger(
                "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3" +
                "A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652" +
                "BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
                "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D1" +
                "19529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8AC" +
                "B70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
                "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD" +
                "7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA",
                16,
            ),
        )
        val G2048_256 = Dh(
            BigInteger(
                "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00" +
                "E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C" +
                "209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B" +
                "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76" +
                "B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E" +
                "F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026" +
                "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103" +
                "A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597",
                16,
            ),
            BigInteger(
                "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3",
                16,
            ),
            BigInteger(
                "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125" +
                "10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62" +
                "901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B" +
                "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193" +
                "B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A" +
                "DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915" +
                "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3" +
                "2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659",
                16,
            ),
        )
    }

    companion object {
        /** Standardized domain parameters (ICAO 9303-11 §9.5.1). */
        fun standard(parameterId: Int): PaceGroup? {
            when (parameterId) {
                0 -> return Rfc5114.G1024_160
                1 -> return Rfc5114.G2048_224
                2 -> return Rfc5114.G2048_256
            }
            val name = when (parameterId) {
                8 -> "secp192r1"
                9 -> "brainpoolP192r1"
                10 -> "secp224r1"
                11 -> "brainpoolP224r1"
                12 -> "secp256r1"
                13 -> "brainpoolP256r1"
                14 -> "brainpoolP320r1"
                15 -> "secp384r1"
                16 -> "brainpoolP384r1"
                17 -> "brainpoolP512r1"
                18 -> "secp521r1"
                else -> return null
            }
            val params = ECNamedCurveTable.getByName(name) ?: return null
            return Ec(params.curve, params.g, params.n)
        }

        private fun randomBelow(bound: BigInteger, random: SecureRandom): BigInteger {
            while (true) {
                val k = BigInteger(bound.bitLength(), random)
                if (k > BigInteger.ZERO && k < bound) return k
            }
        }

        private fun unsigned(value: BigInteger, length: Int): ByteArray {
            val raw = value.toByteArray()
            return when {
                raw.size == length -> raw
                raw.size > length -> raw.copyOfRange(raw.size - length, raw.size)
                else -> ByteArray(length - raw.size) + raw
            }
        }
    }
}

/** PACEInfo with Generic Mapping and standardized domain parameters. */
internal class PaceInfo(val oid: String, val parameterId: Int, val cipher: PaceCipher, val group: PaceGroup) {

    /** OID value bytes as sent in MSE:Set AT. */
    val oidBytes: ByteArray get() = ASN1ObjectIdentifier(oid).encoded.let { it.copyOfRange(2, it.size) }

    companion object {
        private const val PACE_DH_GM = "0.4.0.127.0.7.2.2.4.1"
        private const val PACE_ECDH_GM = "0.4.0.127.0.7.2.2.4.2"

        /** First supported PACEInfo found in EF.CardAccess, or null. */
        fun select(cardAccess: ByteArray): PaceInfo? {
            val infos = ASN1Set.getInstance(ASN1Primitive.fromByteArray(cardAccess))
            for (item in infos) {
                val info = item as? ASN1Sequence ?: continue
                if (info.size() < 3) continue
                val oid = (info.getObjectAt(0) as? ASN1ObjectIdentifier)?.id ?: continue
                if (oid.substringBeforeLast('.') != PACE_DH_GM && oid.substringBeforeLast('.') != PACE_ECDH_GM) continue
                val version = (info.getObjectAt(1) as? ASN1Integer)?.intValueExact() ?: continue
                val parameterId = (info.getObjectAt(2) as? ASN1Integer)?.intValueExact() ?: continue
                if (version != 2) continue
                val cipher = PaceCipher.fromOid(oid) ?: continue
                val group = PaceGroup.standard(parameterId) ?: continue
                val isEc = oid.startsWith(PACE_ECDH_GM)
                if (isEc != (group is PaceGroup.Ec)) continue
                return PaceInfo(oid, parameterId, cipher, group)
            }
            return null
        }
    }
}

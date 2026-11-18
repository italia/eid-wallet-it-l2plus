package it.ipzs.l2plus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom

/** Test vectors from the BSI "Worked Example for Extended Access Control", PACE section. */
class PaceTest {

    private object Ecdh {
        const val CARD_ACCESS = "3181C6300D060804007F00070202020201023012060A04007F000702020302020201020201013012060A04007F0007020204020202010202010D301C060904007F000702020302300C060704007F0007010202010D020101302F060804007F0007020206162368747470733A2F2F7777772E686A702D636F6E73756C74696E672E636F6D2F686F6D65303E060804007F000702020831323012060A04007F00070202030202020102020102301C060904007F000702020302300C060704007F0007010202010D020102"
        const val NONCE = "7D98C00FC6C9E9543BBF94A87073A123"
        const val NONCE_ENC = "CE834CDE69FFBB1D1EB21585CD709F18"
        const val MAP_PCD_PRIV = "752287F5B02DE3C4BC3E17945118C51B23C97278E4CD748048AC56BA5BDC3D46"
        const val MAP_PCD_PUB = "043DD29BBE5907FD21A152ADA4895FAAE7ACC55F5E50EFBFDE5AB0C6EB54F198D615913635F0FDF5BEB383E00355F82D3C41ED0DF2E28363433DFB73856A15DC9F"
        const val MAP_PICC_PUB = "049CFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A"
        const val PCD_PRIV = "9D9A32DF93A57CCE33CA3CDD3457E33A976F293546C73550F397259C93BE0120"
        const val PCD_PUB = "04518BC4E532AD2A9BD6527804D5D665ABD51041037A0CC8AA922804EB501C222B3427388599AFAAE9FBACE2DF93E13C3C4979CD12F0AE3E3C0126028391554582"
        const val PICC_PUB = "04282CF38073036AFAC216AF135BD994DA0C357F10BD4C34AFEA1042B2EB0FD6804DF3658B835AC2E7133F13691184542BB50B109963A4662ABDC08B9763AF4B5B"
        const val SHARED_K = "6E7D077CCD367C2EAA683F1E8EC534302E2D00B6ADAF8A87A6EDA78740F17606"
        const val K_MAC = "73FF268784F72AF833FDC9464049AFC9"
        const val K_ENC = "68406B4162100563D9C901A6154D2901"
        const val TOKEN_PICC = "A2658C2F38600B0F"
        const val TOKEN_PCD = "A27AE7B36573C1D9"
    }

    private object Dh {
        const val NONCE = "FA5B7E3E49753A0DB9178B7B9BD898C8"
        const val NONCE_ENC = "9ABB8864CA0FF1551E620D1EF4E13510"
        const val MAP_PCD_PRIV = "24C3C0E0A3280ECB943345D9DC2A7B72539FDA6FFDF99AB7B6CDDDD1BE425AF3D02C4ED0CDD73EBB4B2EDF8C07FB3A35903F72B84F3771F4EBFB49520D61A8F7C7FB8C9E2ABC24BF4FF9D8DDF381A19380C85B623AB02ACBF6D220F512BF40658322AD209AC0BF9E6F8DB602D5197D252BF6D148510CA1B740AF0F99F33CA5F1"
        const val MAP_PCD_PUB = "23FB3749EA030D2A25B278D2A562047ADE3F01B74F17A15402CB7352CA7D2B3EB71C343DB13D1DEBCE9A3666DBCFC920B49174A602CB47965CAA73DC702489A44D41DB914DE9613DC5E98C94160551C0DF86274B9359BC0490D01B03AD54022DCB4F57FAD6322497D7A1E28D46710F461AFE710FBBBC5F8BA166F4311975EC6C"
        const val MAP_PICC_PUB = "78879F57225AA8080D52ED0FC890A4B25336F699AA89A2D3A189654AF70729E623EA5738B26381E4DA19E004706FACE7B235C2DBF2F38748312F3C98C2DD4882A41947B324AA1259AC22579DB93F7085655AF30889DBB845D9E6783FE42C9F2449400306254C8AE8EE9DD812A804C0B66E8CAFC14F84D8258950A91B44126EE6"
        const val PCD_PRIV = "4BD0E54740F9A028E6A515BFDAF967848C4F5F5FFF65AA0915947FFD1A0DF2FA6981271BC905F3551457B7E03AC3B8066DE4AA406C1171FB43DD939C4BA16175103BA3DEE16419AA248118F90CC36A3D6F4C373652E0C3CCE7F0F1D0C5425B3600F0F0D6A67F004C8BBA33F2B4733C7252445C1DFC4F1107203F71D2EFB28161"
        const val PCD_PUB = "907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD911551B9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08FA8D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236B7747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4"
        const val PICC_PUB = "075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152BD8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1"
        const val SHARED_K = "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E38B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD"
        const val K_MAC = "805A1D27D45A5116F73C54469462B7D8"
        const val K_ENC = "2F7F46ADCC9E7E521B45D192FAFA9126"
        const val TOKEN_PICC = "917F37B5C0E6D8D1"
        const val TOKEN_PCD = "B46DD9BD4D98381F"
    }

    private val password = "123456".toByteArray()

    @Test
    fun `ECDH PACEInfo is selected from EF CardAccess`() {
        val info = PaceInfo.select(hexToBytes(Ecdh.CARD_ACCESS))!!
        assertEquals("0.4.0.127.0.7.2.2.4.2.2", info.oid)
        assertEquals(13, info.parameterId)
        assertEquals(PaceCipher.AES128, info.cipher)
        assertEquals("04007F00070202040202", info.oidBytes.hex())
    }

    @Test
    fun `ECDH generic mapping matches the worked example`() {
        val info = PaceInfo.select(hexToBytes(Ecdh.CARD_ACCESS))!!
        val nonce = Pace.decryptNonce(info.cipher, password, hexToBytes(Ecdh.NONCE_ENC))
        assertEquals(Ecdh.NONCE, nonce.hex())

        val mapPriv = BigInteger(Ecdh.MAP_PCD_PRIV, 16)
        assertEquals(Ecdh.MAP_PCD_PUB, info.group.publicKey(mapPriv).hex())
        val group = info.group.map(nonce, mapPriv, hexToBytes(Ecdh.MAP_PICC_PUB))

        val ephPriv = BigInteger(Ecdh.PCD_PRIV, 16)
        assertEquals(Ecdh.PCD_PUB, group.publicKey(ephPriv).hex())
        val shared = group.sharedSecret(ephPriv, hexToBytes(Ecdh.PICC_PUB))
        assertEquals(Ecdh.SHARED_K, shared.hex())

        val kMac = info.cipher.kdf(shared, 2)
        assertEquals(Ecdh.K_ENC, info.cipher.kdf(shared, 1).hex())
        assertEquals(Ecdh.K_MAC, kMac.hex())
        assertEquals(Ecdh.TOKEN_PCD, info.cipher.authToken(kMac, Pace.authData(info, group, hexToBytes(Ecdh.PICC_PUB))).hex())
        assertEquals(Ecdh.TOKEN_PICC, info.cipher.authToken(kMac, Pace.authData(info, group, hexToBytes(Ecdh.PCD_PUB))).hex())
    }

    @Test
    fun `DH generic mapping matches the worked example`() {
        val group0 = PaceGroup.standard(0)!!
        val cipher = PaceCipher.AES128
        val nonce = Pace.decryptNonce(cipher, password, hexToBytes(Dh.NONCE_ENC))
        assertEquals(Dh.NONCE, nonce.hex())

        val mapPriv = BigInteger(Dh.MAP_PCD_PRIV, 16)
        assertEquals(Dh.MAP_PCD_PUB, group0.publicKey(mapPriv).hex())
        val group = group0.map(nonce, mapPriv, hexToBytes(Dh.MAP_PICC_PUB))

        val ephPriv = BigInteger(Dh.PCD_PRIV, 16)
        assertEquals(Dh.PCD_PUB, group.publicKey(ephPriv).hex())
        val shared = group.sharedSecret(ephPriv, hexToBytes(Dh.PICC_PUB))
        assertEquals(Dh.SHARED_K, shared.hex())

        val kMac = cipher.kdf(shared, 2)
        assertEquals(Dh.K_ENC, cipher.kdf(shared, 1).hex())
        assertEquals(Dh.K_MAC, kMac.hex())
        val info = PaceInfo("0.4.0.127.0.7.2.2.4.1.2", 0, cipher, group0)
        assertEquals(Dh.TOKEN_PCD, cipher.authToken(kMac, Pace.authData(info, group, hexToBytes(Dh.PICC_PUB))).hex())
        assertEquals(Dh.TOKEN_PICC, cipher.authToken(kMac, Pace.authData(info, group, hexToBytes(Dh.PCD_PUB))).hex())
    }

    @Test
    fun `AES secure messaging primitives match the worked example`() {
        val cipher = PaceCipher.AES128
        val kEnc = hexToBytes(Ecdh.K_ENC)
        val ssc1 = ByteArray(16).also { it[15] = 1 }
        val data = hexToBytes("830D44454356434141543030303031")
        assertEquals(
            "BE90237EEB4BA0FF253EA246AE31C8B8",
            cipher.encrypt(kEnc, isoPad(data, 16), cipher.smIv(kEnc, ssc1)).hex(),
        )
        val ssc2 = ByteArray(16).also { it[15] = 2 }
        assertEquals(
            "A89570A68664A7D6",
            cipher.mac(hexToBytes(Ecdh.K_MAC), isoPad(ssc2 + hexToBytes("99029000"), 16)).hex(),
        )
    }

    @Test
    fun `full PACE exchange against a replayed card`() {
        val card = ReplayCard()
        val random = FixedRandom(hexToBytes(Ecdh.MAP_PCD_PRIV), hexToBytes(Ecdh.PCD_PRIV))
        val sm = Pace.establish(CardIo(card) { false }, L2PlusRequest.ValidAccess.Can("123456"), random)
        assertTrue(card.tokenChecked)
        // The session counter starts at zero: the next command uses SSC = 1.
        val wrapped = sm.wrap(hexToBytes("00A4040C07A0000002471001"))
        assertEquals("0CA4040C", wrapped.copyOf(4).hex())
    }

    /** Card side of the ECDH worked example. */
    private class ReplayCard : ApduTransport {
        var tokenChecked = false
        private val cardAccess = hexToBytes(Ecdh.CARD_ACCESS)

        override fun transceive(command: ByteArray): ByteArray {
            val ins = command[1].toInt() and 0xFF
            return when {
                ins == 0xA4 -> ok()
                ins == 0xB0 -> {
                    val offset = ((command[2].toInt() and 0x7F) shl 8) or (command[3].toInt() and 0xFF)
                    val le = (command[4].toInt() and 0xFF).let { if (it == 0) 256 else it }
                    ok(cardAccess.copyOfRange(offset, minOf(cardAccess.size, offset + le)))
                }
                ins == 0x22 -> ok()
                ins == 0x86 -> generalAuthenticate(command)
                else -> byteArrayOf(0x6D, 0x00)
            }
        }

        private var step = 0

        private fun generalAuthenticate(command: ByteArray): ByteArray {
            step++
            return when (step) {
                1 -> ok(Tlv.encode(0x7C, Tlv.encode(0x80, hexToBytes(Ecdh.NONCE_ENC))))
                2 -> {
                    assertTrue(command.hex().contains(Ecdh.MAP_PCD_PUB))
                    ok(Tlv.encode(0x7C, Tlv.encode(0x82, hexToBytes(Ecdh.MAP_PICC_PUB))))
                }
                3 -> {
                    assertTrue(command.hex().contains(Ecdh.PCD_PUB))
                    ok(Tlv.encode(0x7C, Tlv.encode(0x84, hexToBytes(Ecdh.PICC_PUB))))
                }
                else -> {
                    assertTrue(command.hex().contains("8508" + Ecdh.TOKEN_PCD))
                    tokenChecked = true
                    ok(Tlv.encode(0x7C, Tlv.encode(0x86, hexToBytes(Ecdh.TOKEN_PICC))))
                }
            }
        }

        private fun ok(data: ByteArray = ByteArray(0)) = data + byteArrayOf(0x90.toByte(), 0x00)
    }

    /** Returns the given private keys, in order, as random bytes. */
    private class FixedRandom(vararg values: ByteArray) : SecureRandom() {
        private val queue = ArrayDeque(values.toList())

        override fun nextBytes(bytes: ByteArray) {
            val next = queue.removeFirst()
            assertEquals(bytes.size, next.size)
            next.copyInto(bytes)
        }
    }
}

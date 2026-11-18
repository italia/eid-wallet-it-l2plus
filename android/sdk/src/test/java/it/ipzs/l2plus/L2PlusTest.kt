package it.ipzs.l2plus

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date

class L2PlusTest {

    @Test
    fun `check digits match ICAO 9303 examples`() {
        assertEquals('6', MrzAccessKey.checkDigit("L898902C3"))
        assertEquals('2', MrzAccessKey.checkDigit("740812"))
        assertEquals('9', MrzAccessKey.checkDigit("120415"))
        assertEquals('7', MrzAccessKey.checkDigit("V"))
        assertEquals('0', MrzAccessKey.checkDigit("<<<"))
    }

    @Test
    fun `MRZ information with padding and 2000s dates`() {
        assertEquals("L898902C36" + "7408122" + "1204159", MrzAccessKey.mrzInformation("L898902C3", "1974-08-12", "2012-04-15"))
        // Short numbers are padded with '<' to 9 characters.
        assertEquals("L898902C<", MrzAccessKey.mrzInformation("L898902C", "1974-08-12", "2012-04-15").substring(0, 9))
        assertEquals(
            "CA00000AA" + MrzAccessKey.checkDigit("CA00000AA") + "000101" + MrzAccessKey.checkDigit("000101") +
                "310101" + MrzAccessKey.checkDigit("310101"),
            MrzAccessKey.mrzInformation("ca00000aa", "2000-01-01", "2031-01-01"),
        )
        assertTrue(MrzAccessKey.mrzInformation("CA00000AA", "2005-06-30", "2030-01-01").contains("050630"))
    }

    @Test
    fun `invalid MRZ data is rejected before NFC`() {
        expectCode(L2PlusErrorCode.INVALID_MRZ_DATA) { MrzAccessKey.mrzInformation("", "1990-01-01", "2030-01-01") }
        expectCode(L2PlusErrorCode.INVALID_MRZ_DATA) { MrzAccessKey.mrzInformation("CA-0000", "1990-01-01", "2030-01-01") }
        expectCode(L2PlusErrorCode.INVALID_MRZ_DATA) { MrzAccessKey.mrzInformation("CA00000AA", "1990-02-30", "2030-01-01") }
        expectCode(L2PlusErrorCode.INVALID_MRZ_DATA) { MrzAccessKey.mrzInformation("CA00000AA", "01/01/1990", "2030-01-01") }
        expectCode(L2PlusErrorCode.INVALID_MRZ_DATA) { MrzAccessKey.mrzInformation("CA00000AA", "2030-01-01", "1990-01-01") }
    }

    @Test
    fun `CAN and challenge validation`() {
        val challenge = ByteArray(32) { it.toByte() }
        L2PlusRequest.validate(L2PlusAccess.Can("012345"), challenge)
        expectCode(L2PlusErrorCode.INVALID_CAN) { L2PlusRequest.validate(L2PlusAccess.Can("12345"), challenge) }
        expectCode(L2PlusErrorCode.INVALID_CAN) { L2PlusRequest.validate(L2PlusAccess.Can("12345a"), challenge) }
        expectCode(L2PlusErrorCode.INVALID_CHALLENGE) { L2PlusRequest.validate(L2PlusAccess.Can("123456"), ByteArray(0)) }
        expectCode(L2PlusErrorCode.INVALID_CHALLENGE) { L2PlusRequest.validate(L2PlusAccess.Can("123456"), ByteArray(256)) }
    }

    @Test
    fun `challenge is copied`() {
        val challenge = ByteArray(32) { 1 }
        val request = L2PlusRequest.validate(L2PlusAccess.Can("123456"), challenge)
        challenge.fill(9)
        assertArrayEquals(ByteArray(32) { 1 }, request.challenge)
    }

    @Test
    fun `JSON uses the specification names and order`() {
        val r = L2PlusResult(L2PlusResult.Mrtd("AQ==", "Ag==", "Aw=="), L2PlusResult.Ias("BA==", "BQ==", "Bg=="))
        assertEquals(
            "{\"mrtd\":{\"dg1\":\"AQ==\",\"dg11\":\"Ag==\",\"sod_mrtd\":\"Aw==\"}," +
                "\"ias\":{\"ias_pk\":\"BA==\",\"sod_ias\":\"BQ==\",\"challenge_signed\":\"Bg==\"}}",
            r.toJson(),
        )
    }

    // ICAO 9303-11 Appendix D.4
    @Test
    fun `secure messaging matches the ICAO example`() {
        val sm = SecureMessaging(
            PaceCipher.DES3,
            hexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"),
            hexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            hexToBytes("887022120C06C226"),
        )
        assertEquals(
            "0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800",
            sm.wrap(hexToBytes("00A4020C02011E")).hex(),
        )
        val r1 = sm.unwrap(ResponseApdu.parse(hexToBytes("990290008E08FA855A5D4C50A8ED9000")))
        assertEquals(0x9000, r1.sw)
        assertEquals(0, r1.data.size)

        assertEquals("0CB000000D9701048E08ED6705417E96BA5500", sm.wrap(hexToBytes("00B0000004")).hex())
        val r2 = sm.unwrap(ResponseApdu.parse(hexToBytes("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000")))
        assertEquals("60145F01", r2.data.hex())
    }

    @Test
    fun `protected response without MAC or with wrong MAC is rejected`() {
        fun session() = SecureMessaging(
            PaceCipher.DES3,
            hexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"),
            hexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            hexToBytes("887022120C06C226"),
        )
        val noMac = session().also { it.wrap(hexToBytes("00A4020C02011E")) }
        expectCode(L2PlusErrorCode.SECURE_MESSAGING_ERROR) { noMac.unwrap(ResponseApdu.parse(hexToBytes("990290009000"))) }
        val badMac = session().also { it.wrap(hexToBytes("00A4020C02011E")) }
        expectCode(L2PlusErrorCode.SECURE_MESSAGING_ERROR) {
            badMac.unwrap(ResponseApdu.parse(hexToBytes("990290008E08FA855A5D4C50A8EE9000")))
        }
    }

    @Test
    fun `vendor detection from EF ATR`() {
        assertEquals(Ias.Vendor.NXP, Ias.vendorFromAtr(hexToBytes("00112280004301B846041010101047039499")))
        assertEquals(Ias.Vendor.GEMALTO, Ias.vendorFromAtr("xxIasEccRootyy".toByteArray()))
        assertEquals(Ias.Vendor.GEMALTO, Ias.vendorFromAtr(hexToBytes("0047039441C000")))
        assertEquals(null, Ias.vendorFromAtr(hexToBytes("0011223344")))
    }

    @Test
    fun `DER object without trailing padding`() {
        val der = hexToBytes("3003020101")
        assertArrayEquals(der, CardIo.derObject(der + ByteArray(5), L2PlusErrorCode.IAS_READ_FAILED))
        assertArrayEquals(der, CardIo.derObject(der + ByteArray(3) { -1 }, L2PlusErrorCode.IAS_READ_FAILED))
        expectCode(L2PlusErrorCode.IAS_READ_FAILED) { CardIo.derObject(hexToBytes("30030201"), L2PlusErrorCode.IAS_READ_FAILED) }
        expectCode(L2PlusErrorCode.IAS_READ_FAILED) { CardIo.derObject(der + hexToBytes("01"), L2PlusErrorCode.IAS_READ_FAILED) }
    }

    private val pki by lazy { TestPki() }

    @Test
    fun `valid SOD returns the signed hashes`() {
        val dg1 = byteArrayOf(0x61, 0x01, 0x01)
        val dg11 = byteArrayOf(0x6B, 0x01, 0x02)
        val sod = pki.sod(mapOf(1 to dg1, 11 to dg11))
        val signed = SodVerifier.verify(sod, listOf(pki.csca), emptyList(), L2PlusErrorCode.SOD_MRTD_INVALID)
        assertArrayEquals(sha256(dg1), signed.hashes[1])
        assertArrayEquals(sha256(dg11), signed.hashes[11])
        assertArrayEquals(sha256(dg1), SodVerifier.digest(signed.digestAlgorithm, dg1))
    }

    @Test
    fun `unknown anchor is reported apart from a bad signature`() {
        val sod = pki.sod(mapOf(1 to byteArrayOf(1)))
        val other = TestPki(cscaName = "CN=Other CSCA,C=IT")
        expectCode(L2PlusErrorCode.TRUST_ANCHOR_NOT_FOUND) {
            SodVerifier.verify(sod, listOf(other.csca), emptyList(), L2PlusErrorCode.SOD_MRTD_INVALID)
        }
        val tampered = sod.copyOf().also { it[it.size - 10] = (it[it.size - 10] + 1).toByte() }
        expectCode(L2PlusErrorCode.SOD_MRTD_INVALID) {
            SodVerifier.verify(tampered, listOf(pki.csca), emptyList(), L2PlusErrorCode.SOD_MRTD_INVALID)
        }
    }

    @Test
    fun `SOD signed by a DS not issued by the anchor`() {
        // Same name as the trusted CSCA, different keys.
        val rogue = TestPki()
        val sod = rogue.sod(mapOf(1 to byteArrayOf(1)))
        expectCode(L2PlusErrorCode.CERTIFICATE_CHAIN_INVALID) {
            SodVerifier.verify(sod, listOf(pki.csca), emptyList(), L2PlusErrorCode.SOD_MRTD_INVALID)
        }
    }

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    private fun expectCode(code: L2PlusErrorCode, block: () -> Unit) {
        try {
            block()
            fail("Expected $code")
        } catch (e: L2PlusException) {
            assertEquals(code, e.code)
        }
    }

    /** Self-signed CSCA and a Document Signer. */
    private class TestPki(cscaName: String = "CN=Test CSCA,C=IT") {
        private val cscaKeys = rsa()
        private val dsKeys = rsa()
        val csca: X509Certificate = cert(X500Name(cscaName), X500Name(cscaName), cscaKeys.public, cscaKeys.private, ca = true)
        val ds: X509Certificate = cert(X500Name("CN=Test DS,C=IT"), X500Name(cscaName), dsKeys.public, cscaKeys.private, ca = false)

        fun sod(hashes: Map<Int, ByteArray>): ByteArray {
            val alg = AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)
            val entries = ASN1EncodableVector()
            hashes.forEach { (n, data) ->
                entries.add(DERSequence(arrayOf(ASN1Integer(n.toLong()), DEROctetString(MessageDigest.getInstance("SHA-256").digest(data)))))
            }
            val lds = DERSequence(arrayOf(ASN1Integer(0), alg, DERSequence(entries))).encoded
            val gen = CMSSignedDataGenerator()
            val signer = JcaContentSignerBuilder("SHA256withRSA").build(dsKeys.private)
            gen.addSignerInfoGenerator(
                JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build()).build(signer, ds),
            )
            gen.addCertificates(JcaCertStore(listOf(ds)))
            val cms = gen.generate(CMSProcessableByteArray(ASN1ObjectIdentifier("2.23.136.1.1.1"), lds), true)
            return Tlv.encode(0x77, cms.encoded)
        }

        private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

        private fun cert(subject: X500Name, issuer: X500Name, key: PublicKey, signKey: PrivateKey, ca: Boolean): X509Certificate {
            val now = System.currentTimeMillis()
            val builder = JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(now), Date(now - 86_400_000), Date(now + 365L * 86_400_000), subject, key,
            )
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
            builder.addExtension(
                Extension.keyUsage, true,
                KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature),
            )
            return JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder("SHA256withRSA").build(signKey)))
        }
    }
}

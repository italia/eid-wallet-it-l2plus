package it.ipzs.l2plus

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.DefaultAlgorithmNameFinder
import java.security.MessageDigest
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertStore
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Checks a SOD (CMS SignedData, optionally wrapped in tag 0x77): signer signature,
 * chain to the configured anchors, and returns the signed hashes.
 */
internal object SodVerifier {

    private val bc = BouncyCastleProvider()

    /** LDSSecurityObject eContentType (ICAO 9303-10). */
    private val ICAO_LDS_SECURITY_OBJECT = setOf("2.23.136.1.1.1", "1.3.27.1.1.1")

    class SignedHashes(val digestAlgorithm: String, val hashes: Map<Int, ByteArray>)

    fun verify(
        sod: ByteArray,
        anchors: List<X509Certificate>,
        crls: List<X509CRL>,
        invalidCode: L2PlusErrorCode,
        now: Date = Date(),
    ): SignedHashes {
        val cms = try {
            CMSSignedData(unwrap(sod))
        } catch (e: Exception) {
            throw L2PlusException(invalidCode, "Invalid SOD structure", cause = e)
        }
        val signers = cms.signerInfos.signers
        if (signers.size != 1) throw L2PlusException(invalidCode, "SOD must have exactly one signer")
        val signer: SignerInformation = signers.first()

        val holder = cms.certificates.getMatches(null)
            .filterIsInstance<X509CertificateHolder>()
            .filter { signer.sid.match(it) }
            .singleOrNull()
            ?: throw L2PlusException(invalidCode, "Document Signer certificate not found in SOD")
        val dsCert = try {
            JcaX509CertificateConverter().setProvider(bc).getCertificate(holder)
        } catch (e: Exception) {
            throw L2PlusException(invalidCode, "Invalid Document Signer certificate", cause = e)
        }

        val signatureOk = try {
            signer.verify(JcaSimpleSignerInfoVerifierBuilder().setProvider(bc).build(dsCert))
        } catch (e: Exception) {
            false
        }
        if (!signatureOk) throw L2PlusException(invalidCode, "Invalid SOD signature")

        validateChain(dsCert, anchors, crls, now)

        val content = cms.signedContent?.content as? ByteArray
            ?: throw L2PlusException(invalidCode, "Missing signed content")
        return parseSecurityObject(content, cms.signedContentTypeOID, invalidCode)
    }

    fun digest(algorithm: String, data: ByteArray): ByteArray =
        MessageDigest.getInstance(algorithm, bc).digest(data)

    private fun unwrap(sod: ByteArray): ByteArray {
        if (sod.isEmpty()) throw IllegalArgumentException("Empty SOD")
        if ((sod[0].toInt() and 0xFF) != 0x77) return sod
        val h = Tlv.header(sod)
        require(h.totalLength <= sod.size) { "Truncated SOD" }
        return sod.copyOfRange(h.headerLength, h.totalLength)
    }

    private fun validateChain(dsCert: X509Certificate, anchors: List<X509Certificate>, crls: List<X509CRL>, now: Date) {
        val factory = CertificateFactory.getInstance("X.509", bc)
        fun toBc(c: X509Certificate) = factory.generateCertificate(c.encoded.inputStream()) as X509Certificate

        val ds = toBc(dsCert)
        val candidates = anchors.map { toBc(it) }.filter { it.subjectX500Principal == ds.issuerX500Principal }
        if (candidates.isEmpty()) {
            throw L2PlusException(L2PlusErrorCode.TRUST_ANCHOR_NOT_FOUND, "No trust anchor for the Document Signer")
        }
        try {
            val params = PKIXParameters(candidates.map { TrustAnchor(it, null) }.toSet())
            params.date = now
            if (crls.isEmpty()) {
                params.isRevocationEnabled = false
            } else {
                params.isRevocationEnabled = true
                params.addCertStore(CertStore.getInstance("Collection", CollectionCertStoreParameters(crls), bc))
            }
            CertPathValidator.getInstance("PKIX", bc).validate(factory.generateCertPath(listOf(ds)), params)
        } catch (e: CertPathValidatorException) {
            throw L2PlusException(L2PlusErrorCode.CERTIFICATE_CHAIN_INVALID, "Invalid Document Signer chain", cause = e)
        } catch (e: Exception) {
            throw L2PlusException(L2PlusErrorCode.CERTIFICATE_CHAIN_INVALID, "Chain validation failed", cause = e)
        }
    }

    /**
     * LDSSecurityObject:
     * SEQUENCE { version, AlgorithmIdentifier, SEQUENCE OF SEQUENCE { INTEGER number, OCTET STRING hash }, ... }
     */
    private fun parseSecurityObject(content: ByteArray, contentType: String, invalidCode: L2PlusErrorCode): SignedHashes {
        try {
            val seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(content))
            val algId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1))
            val algorithm = digestName(algId.algorithm)
            val hashes = LinkedHashMap<Int, ByteArray>()
            for (item in ASN1Sequence.getInstance(seq.getObjectAt(2))) {
                val entry = ASN1Sequence.getInstance(item)
                val number = ASN1Integer.getInstance(entry.getObjectAt(0)).value.toInt()
                val hash = ASN1OctetString.getInstance(entry.getObjectAt(1)).octets
                if (hashes.put(number, hash) != null) throw IllegalArgumentException("Duplicate hash")
            }
            if (hashes.isEmpty()) throw IllegalArgumentException("No signed hashes")
            return SignedHashes(algorithm, hashes)
        } catch (e: L2PlusException) {
            throw e
        } catch (e: Exception) {
            val hint = if (contentType in ICAO_LDS_SECURITY_OBJECT) "" else " (eContentType $contentType)"
            throw L2PlusException(invalidCode, "Cannot parse SOD content$hint", cause = e)
        }
    }

    private fun digestName(oid: ASN1ObjectIdentifier): String {
        val name = DefaultAlgorithmNameFinder().getAlgorithmName(oid)
        MessageDigest.getInstance(name, bc)
        return name
    }
}

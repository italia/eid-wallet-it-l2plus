@file:Suppress("PropertyName")

package it.ipzs.l2plus

import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.time.format.ResolverStyle

/**
 * Password used to open the chip with PACE. Exactly one is used per read:
 * the SDK never falls back to the other one or to BAC.
 */
sealed class L2PlusAccess {

    /** Card Access Number: the 6 digits printed on the front of the CIE. */
    class Can(can: String) : L2PlusAccess() {
        internal val value: String = can

        override fun toString(): String = "Can(******)"
    }

    /**
     * MRZ data used to derive the PACE password (ICAO 9303-11).
     * Dates are calendar dates formatted as `YYYY-MM-DD`. Padding and check digits are computed by the SDK.
     */
    class Mrz(
        documentNumber: String,
        birthDate: String,
        expiryDate: String,
    ) : L2PlusAccess() {
        internal val documentNumber: String = documentNumber
        internal val birthDate: String = birthDate
        internal val expiryDate: String = expiryDate

        override fun toString(): String = "Mrz(***)"
    }
}

/**
 * Evidence collected from the card. Field names match the `mrtd` and `ias` objects of the
 * `mrtd_validation_jwt` payload defined by the IT-Wallet L2+ specification.
 * Every value is the standard Base64 encoding (with padding) of the bytes read from the card.
 */
data class L2PlusResult(
    val mrtd: Mrtd,
    val ias: Ias,
) {
    data class Mrtd(
        val dg1: String,
        val dg11: String,
        val sod_mrtd: String,
    )

    data class Ias(
        val ias_pk: String,
        val sod_ias: String,
        val challenge_signed: String,
    )

    /** Same JSON, field order included, on Android and iOS. */
    fun toJson(): String =
        "{\"mrtd\":{" +
            "\"dg1\":\"${mrtd.dg1}\"," +
            "\"dg11\":\"${mrtd.dg11}\"," +
            "\"sod_mrtd\":\"${mrtd.sod_mrtd}\"" +
            "},\"ias\":{" +
            "\"ias_pk\":\"${ias.ias_pk}\"," +
            "\"sod_ias\":\"${ias.sod_ias}\"," +
            "\"challenge_signed\":\"${ias.challenge_signed}\"" +
            "}}"
}

/**
 * Trust material used for the local checks. The SDK never downloads anything.
 *
 * @param mrtdTrustAnchors CSCA certificates for the MRTD SOD.
 * @param iasTrustAnchors roots for the IAS SOD; when empty the MRTD anchors are used.
 * @param crls optional CRLs; when present revocation is checked as well.
 */
class L2PlusTrustConfig(
    mrtdTrustAnchors: List<X509Certificate>,
    iasTrustAnchors: List<X509Certificate> = emptyList(),
    crls: List<X509CRL> = emptyList(),
) {
    val mrtdTrustAnchors: List<X509Certificate> = mrtdTrustAnchors.toList()
    val iasTrustAnchors: List<X509Certificate> =
        if (iasTrustAnchors.isEmpty()) this.mrtdTrustAnchors else iasTrustAnchors.toList()
    val crls: List<X509CRL> = crls.toList()
}

enum class L2PlusPhase { INPUT, NFC, PACE, MRTD, IAS, VERIFICATION, INTERNAL }

/** What the app is expected to do after an error. */
enum class L2PlusAction {
    FIX_INPUT,
    ENABLE_NFC,
    RETRY_TAP,
    CHECK_ACCESS_DATA,
    UNSUPPORTED,
    UPDATE_TRUST_MATERIAL,
    REJECT_DOCUMENT,
    NONE,
    CONTACT_SUPPORT,
}

/** Error codes. The same names are used on iOS. */
enum class L2PlusErrorCode(val phase: L2PlusPhase, val action: L2PlusAction) {
    INVALID_CAN(L2PlusPhase.INPUT, L2PlusAction.FIX_INPUT),
    INVALID_MRZ_DATA(L2PlusPhase.INPUT, L2PlusAction.FIX_INPUT),
    INVALID_CHALLENGE(L2PlusPhase.INPUT, L2PlusAction.FIX_INPUT),
    MISSING_TRUST_ANCHORS(L2PlusPhase.INPUT, L2PlusAction.UPDATE_TRUST_MATERIAL),

    NFC_NOT_AVAILABLE(L2PlusPhase.NFC, L2PlusAction.UNSUPPORTED),
    NFC_DISABLED(L2PlusPhase.NFC, L2PlusAction.ENABLE_NFC),
    ALREADY_RUNNING(L2PlusPhase.NFC, L2PlusAction.NONE),
    CANCELLED(L2PlusPhase.NFC, L2PlusAction.NONE),
    TAG_LOST(L2PlusPhase.NFC, L2PlusAction.RETRY_TAP),
    TAG_NOT_SUPPORTED(L2PlusPhase.NFC, L2PlusAction.UNSUPPORTED),

    PACE_NOT_SUPPORTED(L2PlusPhase.PACE, L2PlusAction.UNSUPPORTED),
    /** The card rejected PACE. A wrong CAN or wrong MRZ data is the most likely cause. */
    PACE_FAILED(L2PlusPhase.PACE, L2PlusAction.CHECK_ACCESS_DATA),
    SECURE_MESSAGING_ERROR(L2PlusPhase.MRTD, L2PlusAction.RETRY_TAP),
    MRTD_READ_FAILED(L2PlusPhase.MRTD, L2PlusAction.RETRY_TAP),

    CIE_TYPE_UNKNOWN(L2PlusPhase.IAS, L2PlusAction.UNSUPPORTED),
    IAS_READ_FAILED(L2PlusPhase.IAS, L2PlusAction.RETRY_TAP),
    IAS_SIGN_FAILED(L2PlusPhase.IAS, L2PlusAction.RETRY_TAP),

    SOD_MRTD_INVALID(L2PlusPhase.VERIFICATION, L2PlusAction.REJECT_DOCUMENT),
    DG_HASH_MISMATCH(L2PlusPhase.VERIFICATION, L2PlusAction.REJECT_DOCUMENT),
    SOD_IAS_INVALID(L2PlusPhase.VERIFICATION, L2PlusAction.REJECT_DOCUMENT),
    IAS_KEY_NOT_BOUND(L2PlusPhase.VERIFICATION, L2PlusAction.REJECT_DOCUMENT),
    /** No configured anchor matches the signer. Not the same as an invalid signature. */
    TRUST_ANCHOR_NOT_FOUND(L2PlusPhase.VERIFICATION, L2PlusAction.UPDATE_TRUST_MATERIAL),
    CERTIFICATE_CHAIN_INVALID(L2PlusPhase.VERIFICATION, L2PlusAction.REJECT_DOCUMENT),

    INTERNAL_ERROR(L2PlusPhase.INTERNAL, L2PlusAction.CONTACT_SUPPORT),
}

/**
 * Error returned by the SDK. Messages never contain personal data, access data or keys.
 * @param sw card status word (SW1SW2), when the error comes from a card response.
 */
class L2PlusException(
    val code: L2PlusErrorCode,
    message: String,
    val sw: Int? = null,
    cause: Throwable? = null,
) : Exception(message, cause) {
    val phase: L2PlusPhase get() = code.phase
    val action: L2PlusAction get() = code.action

    override fun toString(): String =
        "L2PlusException(code=$code, phase=$phase, sw=${sw?.let { "%04X".format(it) }}, message=$message)"
}

enum class L2PlusStep { WAITING_FOR_CARD, CARD_DETECTED, PACE, READING_MRTD, READING_IAS, SIGNING_CHALLENGE, VERIFYING }

internal class L2PlusRequest private constructor(
    val access: ValidAccess,
    challenge: ByteArray,
) {
    private val challengeCopy: ByteArray = challenge.copyOf()
    val challenge: ByteArray get() = challengeCopy.copyOf()

    sealed class ValidAccess {
        class Can(val can: String) : ValidAccess()
        class Mrz(val mrzInformation: String) : ValidAccess()
    }

    companion object {
        /** The challenge is sent in a short APDU. */
        const val MAX_CHALLENGE_LENGTH = 255

        fun validate(access: L2PlusAccess, challenge: ByteArray?): L2PlusRequest {
            if (challenge == null || challenge.isEmpty() || challenge.size > MAX_CHALLENGE_LENGTH) {
                throw L2PlusException(
                    L2PlusErrorCode.INVALID_CHALLENGE,
                    "Challenge must be 1 to $MAX_CHALLENGE_LENGTH bytes long",
                )
            }
            val valid = when (access) {
                is L2PlusAccess.Can -> {
                    if (access.value.length != 6 || !access.value.all { it in '0'..'9' }) {
                        throw L2PlusException(L2PlusErrorCode.INVALID_CAN, "CAN must be 6 digits")
                    }
                    ValidAccess.Can(access.value)
                }
                is L2PlusAccess.Mrz -> ValidAccess.Mrz(
                    MrzAccessKey.mrzInformation(access.documentNumber, access.birthDate, access.expiryDate),
                )
            }
            return L2PlusRequest(valid, challenge)
        }
    }
}

/** MRZ information used as PACE password (ICAO 9303-11 §4.4.1, check digits per ICAO 9303-3 §4.9). */
object MrzAccessKey {

    private val ISO_DATE: DateTimeFormatter =
        DateTimeFormatter.ofPattern("uuuu-MM-dd").withResolverStyle(ResolverStyle.STRICT)
    private val MRZ_DATE: DateTimeFormatter = DateTimeFormatter.ofPattern("yyMMdd")

    /** Document number (padded to 9 with '<') + CD + birth date + CD + expiry date + CD. */
    fun mrzInformation(documentNumber: String, birthDate: String, expiryDate: String): String {
        val number = documentNumber.trim().uppercase()
        if (number.isEmpty() || number.length > 22 || !number.all { it in 'A'..'Z' || it in '0'..'9' }) {
            throw L2PlusException(L2PlusErrorCode.INVALID_MRZ_DATA, "Invalid document number")
        }
        val birth = parseDate(birthDate, "birth")
        val expiry = parseDate(expiryDate, "expiry")
        if (!birth.isBefore(expiry)) {
            throw L2PlusException(L2PlusErrorCode.INVALID_MRZ_DATA, "Birth date must precede expiry date")
        }
        val paddedNumber = number.padEnd(9, '<')
        val birthField = birth.format(MRZ_DATE)
        val expiryField = expiry.format(MRZ_DATE)
        return paddedNumber + checkDigit(paddedNumber) +
            birthField + checkDigit(birthField) +
            expiryField + checkDigit(expiryField)
    }

    /** Weights 7-3-1; digits as is, A=10 ... Z=35, '<'=0. */
    fun checkDigit(field: String): Char {
        val weights = intArrayOf(7, 3, 1)
        var sum = 0
        field.forEachIndexed { i, ch ->
            val value = when (ch) {
                in '0'..'9' -> ch - '0'
                in 'A'..'Z' -> ch - 'A' + 10
                '<' -> 0
                else -> throw L2PlusException(L2PlusErrorCode.INVALID_MRZ_DATA, "Invalid MRZ character")
            }
            sum += value * weights[i % 3]
        }
        return '0' + (sum % 10)
    }

    private fun parseDate(value: String, label: String): LocalDate =
        try {
            LocalDate.parse(value.trim(), ISO_DATE)
        } catch (e: DateTimeParseException) {
            throw L2PlusException(L2PlusErrorCode.INVALID_MRZ_DATA, "Invalid $label date, expected YYYY-MM-DD")
        }
}

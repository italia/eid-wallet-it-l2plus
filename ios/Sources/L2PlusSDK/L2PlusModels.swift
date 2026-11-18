//
//  L2PlusModels.swift
//  Public types, errors and input validation.
//

import Foundation

/// Password used to open the chip with PACE. Exactly one is used per read:
/// the SDK never falls back to the other one or to BAC.
public enum L2PlusAccess: CustomStringConvertible {
    /// Card Access Number: the 6 digits printed on the front of the CIE.
    case can(String)
    /// MRZ data. Dates are formatted as `YYYY-MM-DD`; padding and check digits are computed by the SDK.
    case mrz(documentNumber: String, birthDate: String, expiryDate: String)

    public var description: String {
        switch self {
        case .can: return "can(******)"
        case .mrz: return "mrz(***)"
        }
    }
}

/// Evidence collected from the card. Field names match the `mrtd` and `ias` objects of the
/// `mrtd_validation_jwt` payload defined by the IT-Wallet L2+ specification.
/// Every value is the standard Base64 encoding (with padding) of the bytes read from the card.
public struct L2PlusResult: Codable, Equatable {
    public struct Mrtd: Codable, Equatable {
        public let dg1: String
        public let dg11: String
        public let sod_mrtd: String
    }

    public struct Ias: Codable, Equatable {
        public let ias_pk: String
        public let sod_ias: String
        public let challenge_signed: String
    }

    public let mrtd: Mrtd
    public let ias: Ias

    /// Same JSON, field order included, on iOS and Android.
    public func toJson() -> String {
        return "{\"mrtd\":{" +
            "\"dg1\":\"\(mrtd.dg1)\"," +
            "\"dg11\":\"\(mrtd.dg11)\"," +
            "\"sod_mrtd\":\"\(mrtd.sod_mrtd)\"" +
            "},\"ias\":{" +
            "\"ias_pk\":\"\(ias.ias_pk)\"," +
            "\"sod_ias\":\"\(ias.sod_ias)\"," +
            "\"challenge_signed\":\"\(ias.challenge_signed)\"" +
            "}}"
    }
}

/// Trust material used for the local checks (DER X.509 certificates). The SDK never downloads anything.
public struct L2PlusTrustConfig {
    public let mrtdTrustAnchors: [Data]
    public let iasTrustAnchors: [Data]
    /// Optional DER CRLs; when present revocation is checked as well.
    public let crls: [Data]

    public init(mrtdTrustAnchors: [Data], iasTrustAnchors: [Data] = [], crls: [Data] = []) {
        self.mrtdTrustAnchors = mrtdTrustAnchors
        self.iasTrustAnchors = iasTrustAnchors.isEmpty ? mrtdTrustAnchors : iasTrustAnchors
        self.crls = crls
    }
}

public enum L2PlusPhase: String { case input, nfc, pace, mrtd, ias, verification, `internal` }

public enum L2PlusAction: String {
    case fixInput, enableNfc, retryTap, checkAccessData, unsupported, updateTrustMaterial, rejectDocument, none, contactSupport
}

/// Error codes. The same names are used on Android.
public enum L2PlusErrorCode: String {
    case INVALID_CAN, INVALID_MRZ_DATA, INVALID_CHALLENGE, MISSING_TRUST_ANCHORS
    case NFC_NOT_AVAILABLE, NFC_DISABLED, ALREADY_RUNNING, CANCELLED, TAG_LOST, TAG_NOT_SUPPORTED
    case PACE_NOT_SUPPORTED, PACE_FAILED, SECURE_MESSAGING_ERROR, MRTD_READ_FAILED
    case CIE_TYPE_UNKNOWN, IAS_READ_FAILED, IAS_SIGN_FAILED
    case SOD_MRTD_INVALID, DG_HASH_MISMATCH, SOD_IAS_INVALID, IAS_KEY_NOT_BOUND, TRUST_ANCHOR_NOT_FOUND, CERTIFICATE_CHAIN_INVALID
    case INTERNAL_ERROR

    public var phase: L2PlusPhase {
        switch self {
        case .INVALID_CAN, .INVALID_MRZ_DATA, .INVALID_CHALLENGE, .MISSING_TRUST_ANCHORS: return .input
        case .NFC_NOT_AVAILABLE, .NFC_DISABLED, .ALREADY_RUNNING, .CANCELLED, .TAG_LOST, .TAG_NOT_SUPPORTED: return .nfc
        case .PACE_NOT_SUPPORTED, .PACE_FAILED: return .pace
        case .SECURE_MESSAGING_ERROR, .MRTD_READ_FAILED: return .mrtd
        case .CIE_TYPE_UNKNOWN, .IAS_READ_FAILED, .IAS_SIGN_FAILED: return .ias
        case .SOD_MRTD_INVALID, .DG_HASH_MISMATCH, .SOD_IAS_INVALID, .IAS_KEY_NOT_BOUND, .TRUST_ANCHOR_NOT_FOUND, .CERTIFICATE_CHAIN_INVALID: return .verification
        case .INTERNAL_ERROR: return .internal
        }
    }

    public var action: L2PlusAction {
        switch self {
        case .INVALID_CAN, .INVALID_MRZ_DATA, .INVALID_CHALLENGE: return .fixInput
        case .MISSING_TRUST_ANCHORS, .TRUST_ANCHOR_NOT_FOUND: return .updateTrustMaterial
        case .NFC_NOT_AVAILABLE, .TAG_NOT_SUPPORTED, .PACE_NOT_SUPPORTED, .CIE_TYPE_UNKNOWN: return .unsupported
        case .NFC_DISABLED: return .enableNfc
        case .ALREADY_RUNNING, .CANCELLED: return .none
        case .TAG_LOST, .SECURE_MESSAGING_ERROR, .MRTD_READ_FAILED, .IAS_READ_FAILED, .IAS_SIGN_FAILED: return .retryTap
        case .PACE_FAILED: return .checkAccessData
        case .SOD_MRTD_INVALID, .DG_HASH_MISMATCH, .SOD_IAS_INVALID, .IAS_KEY_NOT_BOUND, .CERTIFICATE_CHAIN_INVALID: return .rejectDocument
        case .INTERNAL_ERROR: return .contactSupport
        }
    }
}

/// Error returned by the SDK. Messages never contain personal data, access data or keys.
public struct L2PlusError: Error, CustomStringConvertible {
    public let code: L2PlusErrorCode
    public let message: String
    /// Card status word (SW1SW2), when the error comes from a card response.
    public let sw: UInt16?

    public var phase: L2PlusPhase { code.phase }
    public var action: L2PlusAction { code.action }

    public init(_ code: L2PlusErrorCode, _ message: String, sw: UInt16? = nil) {
        self.code = code
        self.message = message
        self.sw = sw
    }

    public var description: String {
        let swText = sw.map { String(format: ", sw=%04X", $0) } ?? ""
        return "L2PlusError(code=\(code.rawValue), phase=\(phase.rawValue)\(swText), message=\(message))"
    }
}

public enum L2PlusStep: String { case waitingForCard, cardDetected, pace, readingMrtd, readingIas, signingChallenge, verifying }

struct L2PlusRequest {
    enum ValidAccess {
        case can(String)
        case mrz(String)
    }

    static let maxChallengeLength = 255

    let access: ValidAccess
    let challenge: [UInt8]

    static func validate(_ access: L2PlusAccess, challenge: Data) throws -> L2PlusRequest {
        guard !challenge.isEmpty, challenge.count <= maxChallengeLength else {
            throw L2PlusError(.INVALID_CHALLENGE, "Challenge must be 1 to \(maxChallengeLength) bytes long")
        }
        switch access {
        case .can(let can):
            guard can.count == 6, can.allSatisfy({ ("0"..."9").contains($0) }) else {
                throw L2PlusError(.INVALID_CAN, "CAN must be 6 digits")
            }
            return L2PlusRequest(access: .can(can), challenge: [UInt8](challenge))
        case let .mrz(documentNumber, birthDate, expiryDate):
            let info = try MrzAccessKey.mrzInformation(documentNumber: documentNumber, birthDate: birthDate, expiryDate: expiryDate)
            return L2PlusRequest(access: .mrz(info), challenge: [UInt8](challenge))
        }
    }
}

/// MRZ information used as PACE password (ICAO 9303-11 §4.4.1, check digits per ICAO 9303-3 §4.9).
public enum MrzAccessKey {

    /// Document number (padded to 9 with '<') + CD + birth date + CD + expiry date + CD.
    public static func mrzInformation(documentNumber: String, birthDate: String, expiryDate: String) throws -> String {
        let number = documentNumber.trimmingCharacters(in: .whitespaces).uppercased()
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        guard !number.isEmpty, number.count <= 22,
              number.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw L2PlusError(.INVALID_MRZ_DATA, "Invalid document number")
        }
        let birth = try parseDate(birthDate, label: "birth")
        let expiry = try parseDate(expiryDate, label: "expiry")
        guard birth < expiry else {
            throw L2PlusError(.INVALID_MRZ_DATA, "Birth date must precede expiry date")
        }
        let padded = number.count < 9 ? number + String(repeating: "<", count: 9 - number.count) : number
        let b = String(birth.year % 100).leftPad(2) + birth.month.leftPad2 + birth.day.leftPad2
        let e = String(expiry.year % 100).leftPad(2) + expiry.month.leftPad2 + expiry.day.leftPad2
        return padded + String(try checkDigit(padded)) + b + String(try checkDigit(b)) + e + String(try checkDigit(e))
    }

    /// Weights 7-3-1; digits as is, A=10 ... Z=35, '<'=0.
    public static func checkDigit(_ field: String) throws -> Character {
        let weights = [7, 3, 1]
        var sum = 0
        for (i, ch) in field.unicodeScalars.enumerated() {
            let v: Int
            switch ch.value {
            case 48...57: v = Int(ch.value) - 48
            case 65...90: v = Int(ch.value) - 65 + 10
            case 60: v = 0
            default: throw L2PlusError(.INVALID_MRZ_DATA, "Invalid MRZ character")
            }
            sum += v * weights[i % 3]
        }
        return Character(String(sum % 10))
    }

    struct SimpleDate: Comparable {
        let year: Int, month: Int, day: Int
        static func < (l: SimpleDate, r: SimpleDate) -> Bool {
            (l.year, l.month, l.day) < (r.year, r.month, r.day)
        }
    }

    /// Strict `YYYY-MM-DD` parsing (Gregorian calendar, no time zone).
    static func parseDate(_ value: String, label: String) throws -> SimpleDate {
        let parts = value.trimmingCharacters(in: .whitespaces).split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
              let y = Int(parts[0]), let m = Int(parts[1]), let d = Int(parts[2]),
              (1...12).contains(m), d >= 1 else {
            throw L2PlusError(.INVALID_MRZ_DATA, "Invalid \(label) date, expected YYYY-MM-DD")
        }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        let days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
        guard d <= days else {
            throw L2PlusError(.INVALID_MRZ_DATA, "Invalid \(label) date, expected YYYY-MM-DD")
        }
        return SimpleDate(year: y, month: m, day: d)
    }
}

private extension Int {
    var leftPad2: String { String(self).leftPad(2) }
}

private extension String {
    func leftPad(_ n: Int) -> String {
        count >= n ? self : String(repeating: "0", count: n - count) + self
    }
}

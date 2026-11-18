import Foundation
var failures = 0
func check(_ c: Bool, _ m: String) { if !c { failures += 1; print("FAIL: \(m)") } else { print("ok: \(m)") } }
func expectCode(_ code: L2PlusErrorCode, _ m: String, _ f: () throws -> Void) {
    do { try f(); check(false, m) } catch let e as L2PlusError { check(e.code == code, "\(m) [\(e.code)]") } catch { check(false, m) }
}
// ICAO 9303-11 Appendix D.4
let sm = L2PlusSecureMessaging(cipher: .tripleDes, kEnc: l2pHex("979EC13B1CBFE9DCD01AB0FED307EAE5"), kMac: l2pHex("F1CB1F1FB5ADF208806B89DC579DC1F8"), ssc: l2pHex("887022120C06C226"))
check(l2pHexString(try! sm.wrap(l2pHex("00A4020C02011E"))) == "0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800", "SM wrap select")
let r1 = try! sm.unwrap(L2PlusResponse.parse(l2pHex("990290008E08FA855A5D4C50A8ED9000")))
check(r1.sw == 0x9000 && r1.data.isEmpty, "SM unwrap select")
check(l2pHexString(try! sm.wrap(l2pHex("00B0000004"))) == "0CB000000D9701048E08ED6705417E96BA5500", "SM wrap read")
let r2 = try! sm.unwrap(L2PlusResponse.parse(l2pHex("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000")))
check(l2pHexString(r2.data) == "60145F01", "SM unwrap read")
let bad = L2PlusSecureMessaging(cipher: .tripleDes, kEnc: l2pHex("979EC13B1CBFE9DCD01AB0FED307EAE5"), kMac: l2pHex("F1CB1F1FB5ADF208806B89DC579DC1F8"), ssc: l2pHex("887022120C06C226"))
_ = try! bad.wrap(l2pHex("00A4020C02011E"))
expectCode(.SECURE_MESSAGING_ERROR, "SM wrong MAC") { _ = try bad.unwrap(L2PlusResponse.parse(l2pHex("990290008E08FA855A5D4C50A8EE9000"))) }
// RFC 4493
let k = l2pHex("2b7e151628aed2a6abf7158809cf4f3c")
check(l2pHexString(L2PlusCipher.aesCmac(key: k, data: [])!) == "BB1D6929E95937287FA37D129B756746", "CMAC empty")
check(l2pHexString(L2PlusCipher.aesCmac(key: k, data: l2pHex("6bc1bee22e409f96e93d7e117393172a"))!) == "070A16B46B4D4144F79BDD9DD04A287C", "CMAC 16")
check(l2pHexString(L2PlusCipher.aesCmac(key: k, data: l2pHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"))!) == "DFA66747DE9AE63030CA32611497C827", "CMAC 40")
// AES secure messaging length
let a = L2PlusSecureMessaging(cipher: .aes128, kEnc: [UInt8](repeating: 1, count: 16), kMac: [UInt8](repeating: 2, count: 16))
check(try! a.wrap(l2pHex("00B0000004")).count == 4 + 1 + 3 + 10 + 1, "AES wrap length")
// MRZ
let cd1 = try! MrzAccessKey.checkDigit("L898902C3"); let cd2 = try! MrzAccessKey.checkDigit("740812"); let cd3 = try! MrzAccessKey.checkDigit("120415")
check(cd1 == "6" && cd2 == "2" && cd3 == "9", "check digit ICAO")
check(try! MrzAccessKey.checkDigit("V") == "7", "check digit V")
check(try! MrzAccessKey.mrzInformation(documentNumber: "L898902C3", birthDate: "1974-08-12", expiryDate: "2012-04-15") == "L898902C367408122120415" + "9", "MRZ info ICAO")
check(try! MrzAccessKey.mrzInformation(documentNumber: "ca00000aa", birthDate: "2000-01-01", expiryDate: "2031-01-01").contains("000101"), "MRZ year 2000")
check(try! MrzAccessKey.mrzInformation(documentNumber: "L898902C", birthDate: "1974-08-12", expiryDate: "2012-04-15").hasPrefix("L898902C<"), "MRZ padding")
expectCode(.INVALID_MRZ_DATA, "30 February") { _ = try MrzAccessKey.mrzInformation(documentNumber: "CA00000AA", birthDate: "1990-02-30", expiryDate: "2030-01-01") }
expectCode(.INVALID_MRZ_DATA, "date format") { _ = try MrzAccessKey.mrzInformation(documentNumber: "CA00000AA", birthDate: "01/01/1990", expiryDate: "2030-01-01") }
expectCode(.INVALID_CAN, "short CAN") { _ = try L2PlusRequest.validate(.can("12345"), challenge: Data(count: 32)) }
expectCode(.INVALID_CHALLENGE, "empty challenge") { _ = try L2PlusRequest.validate(.can("123456"), challenge: Data()) }
expectCode(.INVALID_CHALLENGE, "challenge 256") { _ = try L2PlusRequest.validate(.can("123456"), challenge: Data(count: 256)) }
let res = L2PlusResult(mrtd: .init(dg1: "AQ==", dg11: "Ag==", sod_mrtd: "Aw=="), ias: .init(ias_pk: "BA==", sod_ias: "BQ==", challenge_signed: "Bg=="))
check(res.toJson() == "{\"mrtd\":{\"dg1\":\"AQ==\",\"dg11\":\"Ag==\",\"sod_mrtd\":\"Aw==\"},\"ias\":{\"ias_pk\":\"BA==\",\"sod_ias\":\"BQ==\",\"challenge_signed\":\"Bg==\"}}", "JSON")
print(failures == 0 ? "ALL PASSED" : "FAILED: \(failures)"); exit(failures == 0 ? 0 : 1)

import Foundation
let dir = CommandLine.arguments[1]
func load(_ f: String) -> [UInt8] { [UInt8](FileManager.default.contents(atPath: dir + "/" + f)!) }
var failures = 0
func check(_ c: Bool, _ m: String) { print(c ? "ok: \(m)" : "FAIL: \(m)"); if !c { failures += 1 } }
func code(_ f: () throws -> Void) -> String { do { try f(); return "OK" } catch let e as L2PlusError { return e.code.rawValue } catch { return "\(error)" } }
let anchor = [Data(load("good/csca.der"))]
let sod = L2PlusTlv.encode(0x77, load("good/sod.cms"))
let signed = try! L2PlusSodVerifier.verify(sod, anchors: anchor, crls: [], invalid: .SOD_MRTD_INVALID)
check(signed.hashes[1] == signed.digest(load("dg1.bin")) && signed.hashes[11] == signed.digest(load("dg11.bin")), "valid SOD, DG1/DG11 hashes")
check(code { _ = try L2PlusSodVerifier.verify(load("good/sod.cms"), anchors: anchor, crls: [], invalid: .SOD_MRTD_INVALID) } == "OK", "SOD without 0x77 wrapper")
check(code { _ = try L2PlusSodVerifier.verify(sod, anchors: [Data(load("other/csca.der"))], crls: [], invalid: .SOD_MRTD_INVALID) } == "TRUST_ANCHOR_NOT_FOUND", "unknown anchor")
check(code { _ = try L2PlusSodVerifier.verify(sod, anchors: [], crls: [], invalid: .SOD_MRTD_INVALID) } == "TRUST_ANCHOR_NOT_FOUND", "no anchors")
check(code { _ = try L2PlusSodVerifier.verify(L2PlusTlv.encode(0x77, load("rogue/sod.cms")), anchors: anchor, crls: [], invalid: .SOD_MRTD_INVALID) } == "TRUST_ANCHOR_NOT_FOUND", "rogue CSCA with the same name is rejected")
check(code { _ = try L2PlusSodVerifier.verify(load("tampered.cms"), anchors: anchor, crls: [], invalid: .SOD_MRTD_INVALID) } == "SOD_MRTD_INVALID", "tampered SOD")
check(code { _ = try L2PlusSodVerifier.verify([0x30, 0x03, 0x02, 0x01, 0x00], anchors: anchor, crls: [], invalid: .SOD_IAS_INVALID) } == "SOD_IAS_INVALID", "not a CMS")
check(L2PlusIas.vendor(fromAtr: l2pHex("00112280004301B846041010101047039499")) == .nxp, "ATR NXP")
check(L2PlusIas.vendor(fromAtr: [UInt8]("xxIasEccRootyy".utf8)) == .gemalto, "ATR Gemalto")
check(L2PlusIas.vendor(fromAtr: l2pHex("0011")) == nil, "unknown ATR")
check(code { _ = try L2PlusCardIO.derObject(l2pHex("3003020101") + [0, 0, 0xFF], .IAS_READ_FAILED) } == "OK", "DER with padding")
check(code { _ = try L2PlusCardIO.derObject(l2pHex("30030201"), .IAS_READ_FAILED) } == "IAS_READ_FAILED", "truncated DER")
check(code { _ = try L2PlusCardIO.derObject(l2pHex("300302010101"), .IAS_READ_FAILED) } == "IAS_READ_FAILED", "DER with trailing data")
print(failures == 0 ? "ALL PASSED" : "FAILED: \(failures)"); exit(failures == 0 ? 0 : 1)

import Foundation

// Test vectors from the BSI "Worked Example for Extended Access Control", PACE section.

var failures = 0
func check(_ c: Bool, _ m: String) { print(c ? "ok: \(m)" : "FAIL: \(m)"); if !c { failures += 1 } }
func hex(_ d: Data?) -> String { d.map { l2pHexString([UInt8]($0)) } ?? "nil" }

enum Ecdh {
    static let cardAccess = "3181C6300D060804007F00070202020201023012060A04007F000702020302020201020201013012060A04007F0007020204020202010202010D301C060904007F000702020302300C060704007F0007010202010D020101302F060804007F0007020206162368747470733A2F2F7777772E686A702D636F6E73756C74696E672E636F6D2F686F6D65303E060804007F000702020831323012060A04007F00070202030202020102020102301C060904007F000702020302300C060704007F0007010202010D020102"
    static let nonce = "7D98C00FC6C9E9543BBF94A87073A123"
    static let nonceEnc = "CE834CDE69FFBB1D1EB21585CD709F18"
    static let mapPcdPriv = "752287F5B02DE3C4BC3E17945118C51B23C97278E4CD748048AC56BA5BDC3D46"
    static let mapPcdPub = "043DD29BBE5907FD21A152ADA4895FAAE7ACC55F5E50EFBFDE5AB0C6EB54F198D615913635F0FDF5BEB383E00355F82D3C41ED0DF2E28363433DFB73856A15DC9F"
    static let mapPiccPub = "049CFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A"
    static let pcdPriv = "9D9A32DF93A57CCE33CA3CDD3457E33A976F293546C73550F397259C93BE0120"
    static let pcdPub = "04518BC4E532AD2A9BD6527804D5D665ABD51041037A0CC8AA922804EB501C222B3427388599AFAAE9FBACE2DF93E13C3C4979CD12F0AE3E3C0126028391554582"
    static let piccPub = "04282CF38073036AFAC216AF135BD994DA0C357F10BD4C34AFEA1042B2EB0FD6804DF3658B835AC2E7133F13691184542BB50B109963A4662ABDC08B9763AF4B5B"
    static let sharedK = "6E7D077CCD367C2EAA683F1E8EC534302E2D00B6ADAF8A87A6EDA78740F17606"
    static let kMac = "73FF268784F72AF833FDC9464049AFC9"
    static let kEnc = "68406B4162100563D9C901A6154D2901"
    static let tokenPicc = "A2658C2F38600B0F"
    static let tokenPcd = "A27AE7B36573C1D9"
}

enum Dh {
    static let nonce = "FA5B7E3E49753A0DB9178B7B9BD898C8"
    static let nonceEnc = "9ABB8864CA0FF1551E620D1EF4E13510"
    static let mapPcdPriv = "24C3C0E0A3280ECB943345D9DC2A7B72539FDA6FFDF99AB7B6CDDDD1BE425AF3D02C4ED0CDD73EBB4B2EDF8C07FB3A35903F72B84F3771F4EBFB49520D61A8F7C7FB8C9E2ABC24BF4FF9D8DDF381A19380C85B623AB02ACBF6D220F512BF40658322AD209AC0BF9E6F8DB602D5197D252BF6D148510CA1B740AF0F99F33CA5F1"
    static let mapPcdPub = "23FB3749EA030D2A25B278D2A562047ADE3F01B74F17A15402CB7352CA7D2B3EB71C343DB13D1DEBCE9A3666DBCFC920B49174A602CB47965CAA73DC702489A44D41DB914DE9613DC5E98C94160551C0DF86274B9359BC0490D01B03AD54022DCB4F57FAD6322497D7A1E28D46710F461AFE710FBBBC5F8BA166F4311975EC6C"
    static let mapPiccPub = "78879F57225AA8080D52ED0FC890A4B25336F699AA89A2D3A189654AF70729E623EA5738B26381E4DA19E004706FACE7B235C2DBF2F38748312F3C98C2DD4882A41947B324AA1259AC22579DB93F7085655AF30889DBB845D9E6783FE42C9F2449400306254C8AE8EE9DD812A804C0B66E8CAFC14F84D8258950A91B44126EE6"
    static let pcdPriv = "4BD0E54740F9A028E6A515BFDAF967848C4F5F5FFF65AA0915947FFD1A0DF2FA6981271BC905F3551457B7E03AC3B8066DE4AA406C1171FB43DD939C4BA16175103BA3DEE16419AA248118F90CC36A3D6F4C373652E0C3CCE7F0F1D0C5425B3600F0F0D6A67F004C8BBA33F2B4733C7252445C1DFC4F1107203F71D2EFB28161"
    static let pcdPub = "907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD911551B9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08FA8D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236B7747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4"
    static let piccPub = "075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152BD8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1"
    static let sharedK = "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E38B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD"
    static let kMac = "805A1D27D45A5116F73C54469462B7D8"
    static let kEnc = "2F7F46ADCC9E7E521B45D192FAFA9126"
    static let tokenPicc = "917F37B5C0E6D8D1"
    static let tokenPcd = "B46DD9BD4D98381F"
}

let password = Array("123456".utf8)

// ECDH, brainpoolP256r1, AES-128
let info = L2PlusPaceInfo.select(cardAccess: l2pHex(Ecdh.cardAccess))!
check(l2pHexString(info.oid) == "04007F00070202040202" && info.parameterId == 13, "PACEInfo selection")
let nonce = try! L2PlusPace.decryptNonce(info.cipher, password: password, encrypted: l2pHex(Ecdh.nonceEnc))
check(l2pHexString(nonce) == Ecdh.nonce, "ECDH nonce")
let mapPriv = Data(l2pHex(Ecdh.mapPcdPriv))
check(hex(info.group.publicKey(forPrivateKey: mapPriv)) == Ecdh.mapPcdPub, "ECDH mapping public key")
let mapped = info.group.map(withNonce: Data(nonce), privateKey: mapPriv, peerPublicKey: Data(l2pHex(Ecdh.mapPiccPub)))!
let ephPriv = Data(l2pHex(Ecdh.pcdPriv))
check(hex(mapped.publicKey(forPrivateKey: ephPriv)) == Ecdh.pcdPub, "ECDH ephemeral public key on mapped group")
let shared = [UInt8](mapped.sharedSecret(withPrivateKey: ephPriv, peerPublicKey: Data(l2pHex(Ecdh.piccPub)))!)
check(l2pHexString(shared) == Ecdh.sharedK, "ECDH shared secret")
let kMac = info.cipher.kdf(shared, counter: 2)
check(l2pHexString(info.cipher.kdf(shared, counter: 1)) == Ecdh.kEnc && l2pHexString(kMac) == Ecdh.kMac, "ECDH session keys")
check(l2pHexString(info.cipher.authToken(kMac: kMac, authData: info.authData(group: mapped, publicKey: l2pHex(Ecdh.piccPub)))!) == Ecdh.tokenPcd, "ECDH terminal token")
check(l2pHexString(info.cipher.authToken(kMac: kMac, authData: info.authData(group: mapped, publicKey: l2pHex(Ecdh.pcdPub)))!) == Ecdh.tokenPicc, "ECDH card token")

// AES secure messaging primitives
let kEnc = l2pHex(Ecdh.kEnc)
let iv = L2PlusCipher.aes128.smIv(kEnc: kEnc, ssc: [UInt8](repeating: 0, count: 15) + [1])!
check(l2pHexString(L2PlusCipher.aes128.encrypt(key: kEnc, data: l2pPad(l2pHex("830D44454356434141543030303031"), blockSize: 16), iv: iv)!) == "BE90237EEB4BA0FF253EA246AE31C8B8", "AES SM encryption")
check(l2pHexString(L2PlusCipher.aes128.mac(key: kMac, data: l2pPad([UInt8](repeating: 0, count: 15) + [2] + l2pHex("99029000"), blockSize: 16))!) == "A89570A68664A7D6", "AES SM MAC")

// DH, RFC 5114 1024-bit group, AES-128
let dh = L2PlusPaceGroup(parameterId: 0)!
let dhNonce = try! L2PlusPace.decryptNonce(.aes128, password: password, encrypted: l2pHex(Dh.nonceEnc))
check(l2pHexString(dhNonce) == Dh.nonce, "DH nonce")
let dhMapPriv = Data(l2pHex(Dh.mapPcdPriv))
check(hex(dh.publicKey(forPrivateKey: dhMapPriv)) == Dh.mapPcdPub, "DH mapping public key")
let dhMapped = dh.map(withNonce: Data(dhNonce), privateKey: dhMapPriv, peerPublicKey: Data(l2pHex(Dh.mapPiccPub)))!
let dhEph = Data(l2pHex(Dh.pcdPriv))
check(hex(dhMapped.publicKey(forPrivateKey: dhEph)) == Dh.pcdPub, "DH ephemeral public key on mapped group")
let dhShared = [UInt8](dhMapped.sharedSecret(withPrivateKey: dhEph, peerPublicKey: Data(l2pHex(Dh.piccPub)))!)
check(l2pHexString(dhShared) == Dh.sharedK, "DH shared secret")
let dhKMac = L2PlusCipher.aes128.kdf(dhShared, counter: 2)
check(l2pHexString(L2PlusCipher.aes128.kdf(dhShared, counter: 1)) == Dh.kEnc && l2pHexString(dhKMac) == Dh.kMac, "DH session keys")
let dhInfo = L2PlusPaceInfo(oid: l2pHex("04007F00070202040102"), parameterId: 0, cipher: .aes128, group: dh)
check(l2pHexString(L2PlusCipher.aes128.authToken(kMac: dhKMac, authData: dhInfo.authData(group: dhMapped, publicKey: l2pHex(Dh.piccPub)))!) == Dh.tokenPcd, "DH terminal token")
check(l2pHexString(L2PlusCipher.aes128.authToken(kMac: dhKMac, authData: dhInfo.authData(group: dhMapped, publicKey: l2pHex(Dh.pcdPub)))!) == Dh.tokenPicc, "DH card token")

// Invalid peer keys are rejected
check(info.group.map(withNonce: Data(nonce), privateKey: mapPriv, peerPublicKey: Data([0x04] + [UInt8](repeating: 1, count: 64))) == nil, "point not on curve rejected")
check(dh.sharedSecret(withPrivateKey: dhMapPriv, peerPublicKey: Data([0x01])) == nil, "DH key 1 rejected")

// Full exchange against a replayed card (ECDH worked example)
final class ReplayCard: L2PlusTransport {
    var step = 0
    var tokenChecked = false
    let cardAccess = l2pHex(Ecdh.cardAccess)

    func transceive(_ apdu: [UInt8]) async throws -> [UInt8] {
        let ok: ([UInt8]) -> [UInt8] = { $0 + [0x90, 0x00] }
        switch apdu[1] {
        case 0xA4, 0x22: return ok([])
        case 0xB0:
            let offset = Int(apdu[2] & 0x7F) << 8 | Int(apdu[3])
            let le = apdu[4] == 0 ? 256 : Int(apdu[4])
            return ok(Array(cardAccess[offset..<min(cardAccess.count, offset + le)]))
        case 0x86:
            step += 1
            let command = l2pHexString(apdu)
            switch step {
            case 1: return ok(L2PlusTlv.encode(0x7C, L2PlusTlv.encode(0x80, l2pHex(Ecdh.nonceEnc))))
            case 2:
                check(command.contains(Ecdh.mapPcdPub), "replay: mapping key sent")
                return ok(L2PlusTlv.encode(0x7C, L2PlusTlv.encode(0x82, l2pHex(Ecdh.mapPiccPub))))
            case 3:
                check(command.contains(Ecdh.pcdPub), "replay: ephemeral key sent")
                return ok(L2PlusTlv.encode(0x7C, L2PlusTlv.encode(0x84, l2pHex(Ecdh.piccPub))))
            default:
                tokenChecked = command.contains("8508" + Ecdh.tokenPcd)
                return ok(L2PlusTlv.encode(0x7C, L2PlusTlv.encode(0x86, l2pHex(Ecdh.tokenPicc))))
            }
        default: return [0x6D, 0x00]
        }
    }
}

let replay = ReplayCard()
var keys = [Data(l2pHex(Ecdh.mapPcdPriv)), Data(l2pHex(Ecdh.pcdPriv))]
do {
    let sm = try await L2PlusPace.establish(L2PlusCardIO(transport: replay, isCancelled: { false }), access: .can("123456"),
                                            keyGenerator: { _ in keys.removeFirst() })
    check(replay.tokenChecked, "replay: terminal token accepted")
    check(try sm.wrap(l2pHex("00A4040C07A0000002471001")).prefix(4) == [0x0C, 0xA4, 0x04, 0x0C], "replay: secure messaging ready")
} catch {
    check(false, "replay: \(error)")
}

print(failures == 0 ? "ALL PASSED" : "FAILED: \(failures)")
exit(failures == 0 ? 0 : 1)

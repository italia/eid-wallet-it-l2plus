//
//  L2PlusPaceGroup.m
//

#import "L2PlusPaceGroup.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

// RFC 5114 §2.1-2.3: PACE domain parameter IDs 0, 1 and 2.
static const struct { const char *p, *q, *g; } kRfc5114[] = {
    { /* 1024/160 */
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
        "6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF"
        "ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
        "F518AA8781A8DF278ABA4E7D64B7CB9D49462353",
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31"
        "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4"
        "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5" },
    { /* 2048/224 */
        "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75"
        "E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A6"
        "6D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207"
        "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A3170918836"
        "81286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A074"
        "15987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8"
        "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29"
        "E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F",
        "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB",
        "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3"
        "A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652"
        "BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A"
        "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D1"
        "19529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8AC"
        "B70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381"
        "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD"
        "7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA" },
    { /* 2048/256 */
        "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00"
        "E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C"
        "209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
        "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76"
        "B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E"
        "F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
        "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103"
        "A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597",
        "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3",
        "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125"
        "10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62"
        "901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
        "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193"
        "B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A"
        "DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
        "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3"
        "2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659" },
};

static int curveForParameterId(NSInteger parameterId)
{
    switch (parameterId) {
        case 8: return NID_X9_62_prime192v1;
        case 9: return NID_brainpoolP192r1;
        case 10: return NID_secp224r1;
        case 11: return NID_brainpoolP224r1;
        case 12: return NID_X9_62_prime256v1;
        case 13: return NID_brainpoolP256r1;
        case 14: return NID_brainpoolP320r1;
        case 15: return NID_secp384r1;
        case 16: return NID_brainpoolP384r1;
        case 17: return NID_brainpoolP512r1;
        case 18: return NID_secp521r1;
        default: return NID_undef;
    }
}

static NSData *bnToData(const BIGNUM *bn, int length)
{
    NSMutableData *out = [NSMutableData dataWithLength:(NSUInteger)length];
    if (BN_bn2binpad(bn, out.mutableBytes, length) != length) return nil;
    return out;
}

static BIGNUM *dataToBn(NSData *data)
{
    return BN_bin2bn(data.bytes, (int)data.length, NULL);
}

@implementation L2PlusPaceGroup {
    // ECDH
    EC_GROUP *_group;
    // DH
    BIGNUM *_p, *_q, *_g;
}

+ (instancetype)groupWithParameterId:(NSInteger)parameterId
{
    if (parameterId >= 0 && parameterId <= 2) {
        L2PlusPaceGroup *g = [[L2PlusPaceGroup alloc] init];
        BN_hex2bn(&g->_p, kRfc5114[parameterId].p);
        BN_hex2bn(&g->_q, kRfc5114[parameterId].q);
        BN_hex2bn(&g->_g, kRfc5114[parameterId].g);
        return (g->_p && g->_q && g->_g) ? g : nil;
    }
    int nid = curveForParameterId(parameterId);
    if (nid == NID_undef) return nil;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) return nil;
    L2PlusPaceGroup *g = [[L2PlusPaceGroup alloc] init];
    g->_group = group;
    return g;
}

- (void)dealloc
{
    EC_GROUP_free(_group);
    BN_free(_p);
    BN_free(_q);
    BN_free(_g);
}

- (BOOL)isEllipticCurve
{
    return _group != NULL;
}

- (int)fieldLength
{
    return _group ? (EC_GROUP_get_degree(_group) + 7) / 8 : BN_num_bytes(_p);
}

- (NSData *)generatePrivateKey
{
    const BIGNUM *order = _group ? EC_GROUP_get0_order(_group) : _q;
    BIGNUM *k = BN_new();
    NSData *out = nil;
    if (k != NULL) {
        do {
            if (BN_priv_rand_range(k, order) != 1) { BN_free(k); return nil; }
        } while (BN_is_zero(k));
        out = bnToData(k, BN_num_bytes(order));
    }
    BN_clear_free(k);
    return out;
}

- (NSData *)publicKeyForPrivateKey:(NSData *)privateKey
{
    BIGNUM *k = dataToBn(privateKey);
    BN_CTX *ctx = BN_CTX_new();
    NSData *out = nil;
    if (k && ctx) {
        if (_group) {
            EC_POINT *pub = EC_POINT_new(_group);
            if (pub && EC_POINT_mul(_group, pub, k, NULL, NULL, ctx) == 1) out = [self encodePoint:pub ctx:ctx];
            EC_POINT_free(pub);
        } else {
            BIGNUM *y = BN_new();
            if (y && BN_mod_exp(y, _g, k, _p, ctx) == 1) out = bnToData(y, [self fieldLength]);
            BN_free(y);
        }
    }
    BN_clear_free(k);
    BN_CTX_free(ctx);
    return out;
}

- (NSData *)sharedSecretWithPrivateKey:(NSData *)privateKey peerPublicKey:(NSData *)peerPublicKey
{
    BN_CTX *ctx = BN_CTX_new();
    NSData *out = nil;
    if (ctx == NULL) return nil;
    if (_group) {
        EC_POINT *shared = [self agree:privateKey peer:peerPublicKey ctx:ctx];
        BIGNUM *x = BN_new();
        if (shared && x && EC_POINT_get_affine_coordinates(_group, shared, x, NULL, ctx) == 1) {
            out = bnToData(x, [self fieldLength]);
        }
        BN_clear_free(x);
        EC_POINT_clear_free(shared);
    } else {
        BIGNUM *z = [self agreeDh:privateKey peer:peerPublicKey ctx:ctx];
        if (z) out = bnToData(z, [self fieldLength]);
        BN_clear_free(z);
    }
    BN_CTX_free(ctx);
    return out;
}

- (L2PlusPaceGroup *)mapWithNonce:(NSData *)nonce privateKey:(NSData *)privateKey peerPublicKey:(NSData *)peerPublicKey
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *s = dataToBn(nonce);
    L2PlusPaceGroup *mapped = nil;
    if (ctx == NULL || s == NULL) goto done;

    if (_group) {
        EC_POINT *h = [self agree:privateKey peer:peerPublicKey ctx:ctx];
        EC_POINT *generator = EC_POINT_new(_group);
        EC_GROUP *group = EC_GROUP_dup(_group);
        // G' = s·G + 1·H
        if (h && generator && group &&
            EC_POINT_mul(_group, generator, s, h, BN_value_one(), ctx) == 1 &&
            !EC_POINT_is_at_infinity(_group, generator) &&
            EC_GROUP_set_generator(group, generator, EC_GROUP_get0_order(_group), EC_GROUP_get0_cofactor(_group)) == 1) {
            mapped = [[L2PlusPaceGroup alloc] init];
            mapped->_group = group;
            group = NULL;
        }
        EC_GROUP_free(group);
        EC_POINT_free(generator);
        EC_POINT_clear_free(h);
    } else {
        BIGNUM *h = [self agreeDh:privateKey peer:peerPublicKey ctx:ctx];
        BIGNUM *gs = BN_new();
        BIGNUM *generator = BN_new();
        // g' = g^s · h mod p
        if (h && gs && generator &&
            BN_mod_exp(gs, _g, s, _p, ctx) == 1 &&
            BN_mod_mul(generator, gs, h, _p, ctx) == 1 &&
            BN_cmp(generator, BN_value_one()) > 0) {
            mapped = [[L2PlusPaceGroup alloc] init];
            mapped->_p = BN_dup(_p);
            mapped->_q = BN_dup(_q);
            mapped->_g = generator;
            generator = NULL;
        }
        BN_free(generator);
        BN_clear_free(gs);
        BN_clear_free(h);
    }

done:
    BN_clear_free(s);
    BN_CTX_free(ctx);
    return mapped;
}

#pragma mark - Helpers

- (NSData *)encodePoint:(const EC_POINT *)point ctx:(BN_CTX *)ctx
{
    size_t length = EC_POINT_point2oct(_group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    if (length == 0) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:length];
    if (EC_POINT_point2oct(_group, point, POINT_CONVERSION_UNCOMPRESSED, out.mutableBytes, length, ctx) != length) return nil;
    return out;
}

/// privateKey · peer, after checking that the peer point is on the curve. Caller frees.
- (EC_POINT *)agree:(NSData *)privateKey peer:(NSData *)peerPublicKey ctx:(BN_CTX *)ctx
{
    EC_POINT *peer = EC_POINT_new(_group);
    EC_POINT *shared = EC_POINT_new(_group);
    BIGNUM *k = dataToBn(privateKey);
    BOOL ok = peer && shared && k &&
        EC_POINT_oct2point(_group, peer, peerPublicKey.bytes, peerPublicKey.length, ctx) == 1 &&
        !EC_POINT_is_at_infinity(_group, peer) &&
        EC_POINT_is_on_curve(_group, peer, ctx) == 1 &&
        EC_POINT_mul(_group, shared, NULL, peer, k, ctx) == 1 &&
        !EC_POINT_is_at_infinity(_group, shared);
    BN_clear_free(k);
    EC_POINT_free(peer);
    if (!ok) { EC_POINT_clear_free(shared); return NULL; }
    return shared;
}

/// peer^privateKey mod p, after checking 1 < peer < p-1 and peer^q = 1. Caller frees.
- (BIGNUM *)agreeDh:(NSData *)privateKey peer:(NSData *)peerPublicKey ctx:(BN_CTX *)ctx
{
    BIGNUM *y = dataToBn(peerPublicKey);
    BIGNUM *k = dataToBn(privateKey);
    BIGNUM *pMinusOne = BN_dup(_p);
    BIGNUM *check = BN_new();
    BIGNUM *z = BN_new();
    BOOL ok = y && k && pMinusOne && check && z &&
        BN_sub_word(pMinusOne, 1) == 1 &&
        BN_cmp(y, BN_value_one()) > 0 && BN_cmp(y, pMinusOne) < 0 &&
        BN_mod_exp(check, y, _q, _p, ctx) == 1 && BN_is_one(check) &&
        BN_mod_exp(z, y, k, _p, ctx) == 1;
    BN_free(y);
    BN_clear_free(k);
    BN_free(pMinusOne);
    BN_free(check);
    if (!ok) { BN_clear_free(z); return NULL; }
    return z;
}

@end

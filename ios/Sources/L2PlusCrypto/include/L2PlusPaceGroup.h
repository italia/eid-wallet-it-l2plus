//
//  L2PlusPaceGroup.h
//  Key agreement groups for PACE Generic Mapping (ICAO 9303-11 §4.4.3.3.1).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// ECDH or DH group with standardized domain parameters. Keys and points are big-endian byte strings;
/// EC public keys use the uncompressed encoding (04 || X || Y).
@interface L2PlusPaceGroup : NSObject

/// Standardized domain parameters by PACE parameter ID (0-2 DH, 8-18 ECDH). Nil if unsupported.
+ (nullable instancetype)groupWithParameterId:(NSInteger)parameterId;

@property (nonatomic, readonly) BOOL isEllipticCurve;

- (nullable NSData *)generatePrivateKey;

- (nullable NSData *)publicKeyForPrivateKey:(NSData *)privateKey;

/// x coordinate of the shared point (ECDH) or Z (DH), left-padded to the field size.
- (nullable NSData *)sharedSecretWithPrivateKey:(NSData *)privateKey peerPublicKey:(NSData *)peerPublicKey;

/// Generic Mapping: returns the group with generator s·G + H (ECDH) or g^s·h (DH).
- (nullable L2PlusPaceGroup *)mapWithNonce:(NSData *)nonce privateKey:(NSData *)privateKey peerPublicKey:(NSData *)peerPublicKey;

@end

NS_ASSUME_NONNULL_END

//
//  L2PlusCms.h
//  CMS SignedData (SOD) verification: signature, chain to the given anchors, signed content.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, L2PlusCmsStatus) {
    L2PlusCmsStatusOk = 0,
    /// Invalid CMS structure, or not exactly one signer.
    L2PlusCmsStatusMalformed = 1,
    /// Invalid signature or content digest.
    L2PlusCmsStatusSignatureInvalid = 2,
    /// No anchor matches the Document Signer issuer.
    L2PlusCmsStatusAnchorNotFound = 3,
    /// Invalid chain (validity, revocation, certificate signature, constraints).
    L2PlusCmsStatusChainInvalid = 4,
};

@interface L2PlusCmsResult : NSObject
@property (nonatomic) L2PlusCmsStatus status;
@property (nonatomic, strong, nullable) NSData *content;
@property (nonatomic, strong, nullable) NSString *contentType;
@end

@interface L2PlusCms : NSObject

/// @param cms DER CMS SignedData, without the 0x77 wrapper
/// @param anchors DER root certificates
/// @param crls DER CRLs; when present, revocation is checked
+ (L2PlusCmsResult *)verify:(NSData *)cms anchors:(NSArray<NSData *> *)anchors crls:(NSArray<NSData *> *)crls;

@end

NS_ASSUME_NONNULL_END

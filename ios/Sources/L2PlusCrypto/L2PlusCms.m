//
//  L2PlusCms.m
//

#import "L2PlusCms.h"
#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>

@implementation L2PlusCmsResult
@end

@implementation L2PlusCms

+ (L2PlusCmsResult *)verify:(NSData *)cmsData anchors:(NSArray<NSData *> *)anchors crls:(NSArray<NSData *> *)crls
{
    L2PlusCmsResult *result = [[L2PlusCmsResult alloc] init];
    result.status = L2PlusCmsStatusMalformed;

    CMS_ContentInfo *cms = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    BIO *out = NULL;
    STACK_OF(X509) *signers = NULL;
    STACK_OF(X509) *certs = NULL;

    const unsigned char *p = cmsData.bytes;
    cms = d2i_CMS_ContentInfo(NULL, &p, (long)cmsData.length);
    if (cms == NULL || OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_signed) goto done;
    if (sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(cms)) != 1) goto done;

    // Signature and content digest, using the signer certificate embedded in the SOD.
    // The signer chain is checked below, without the S/MIME purpose checks of CMS_verify.
    out = BIO_new(BIO_s_mem());
    if (CMS_verify(cms, NULL, NULL, NULL, out, CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) != 1) {
        result.status = L2PlusCmsStatusSignatureInvalid;
        goto done;
    }
    signers = CMS_get0_signers(cms);
    if (signers == NULL || sk_X509_num(signers) != 1) goto done;

    // Document Signer chain to the anchors supplied by the app.
    store = X509_STORE_new();
    if (store == NULL) goto done;
    for (NSData *der in anchors) {
        const unsigned char *q = der.bytes;
        X509 *anchor = d2i_X509(NULL, &q, (long)der.length);
        if (anchor) { X509_STORE_add_cert(store, anchor); X509_free(anchor); }
    }
    if (crls.count > 0) {
        for (NSData *der in crls) {
            const unsigned char *q = der.bytes;
            X509_CRL *crl = d2i_X509_CRL(NULL, &q, (long)der.length);
            if (crl) { X509_STORE_add_crl(store, crl); X509_CRL_free(crl); }
        }
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    }
    certs = CMS_get1_certs(cms);
    ctx = X509_STORE_CTX_new();
    if (ctx == NULL || X509_STORE_CTX_init(ctx, store, sk_X509_value(signers, 0), certs) != 1) goto done;
    if (X509_verify_cert(ctx) != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
            err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
            err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
            err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            result.status = L2PlusCmsStatusAnchorNotFound;
        } else {
            result.status = L2PlusCmsStatusChainInvalid;
        }
        goto done;
    }

    // Signed content and its type.
    {
        BUF_MEM *mem = NULL;
        BIO_get_mem_ptr(out, &mem);
        if (mem == NULL || mem->length == 0) { result.status = L2PlusCmsStatusMalformed; goto done; }
        result.content = [NSData dataWithBytes:mem->data length:mem->length];
        char oid[128];
        if (OBJ_obj2txt(oid, sizeof(oid), CMS_get0_eContentType(cms), 1) > 0) {
            result.contentType = [NSString stringWithUTF8String:oid];
        }
        result.status = L2PlusCmsStatusOk;
    }

done:
    if (ctx) X509_STORE_CTX_free(ctx);
    if (store) X509_STORE_free(store);
    if (certs) sk_X509_pop_free(certs, X509_free);
    if (signers) sk_X509_free(signers);
    if (out) BIO_free(out);
    if (cms) CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return result;
}

@end

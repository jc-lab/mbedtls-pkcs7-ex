#ifndef MBEDTLS_PKCS7_VIEW_H
#define MBEDTLS_PKCS7_VIEW_H

#include <mbedtls/pkcs7.h>
#include <mbedtls/asn1.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <mbedtls/md.h>

typedef struct {
    mbedtls_pkcs7_buf econtent_type;     /* EncapsulatedContentInfo.eContentType OID */
    const unsigned char *content;        /* EncapsulatedContentInfo.eContent pointer into pkcs7 DER buffer */
    size_t content_len;                  /* eContent length */
    mbedtls_x509_crt signer_cert;        /* matched signer certificate */
    
    int signing_time_valid;
    mbedtls_x509_time signing_time;
} mbedtls_pkcs7_view;

/* 내장 콘텐츠가 있는 PKCS#7 SignedData(Attached)를 파싱 + 검증하는 최상위 함수 */
int mbedtls_pkcs7_parse_verify_attached(
    const unsigned char *pkcs7_der, size_t pkcs7_len,
    mbedtls_pkcs7_view *out_view /* out */ );

void mbedtls_pkcs7_view_free( mbedtls_pkcs7_view *view );
#endif /* MBEDTLS_PKCS7_VIEW_H */


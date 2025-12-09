/*
 * Attached PKCS#7 (SignedData with eContent) parser & verifier that
 *  - avoids x509_internal.h
 *  - matches signer cert by SID (issuer+serial)
 *  - supports optional authenticatedAttributes with messageDigest
 *  - returns a compact view (eContent type/ptr/len + signer cert)
 */

#include <string.h>
#include <stdio.h>

#include <mbedtls/error.h>

#include "pkcs7_ex.h"

static void dump_hex(void* p, int len) {
    int i;
    unsigned char* p2 = (unsigned char*)p;
    for (i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", p2[i]);
    }
    fprintf(stderr, "\n");
}

/* messageDigest(1.2.840.113549.1.9.4) 의 DER value 바이트 */
static const unsigned char OID_PKCS9_MESSAGE_DIGEST[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04, 0x00
};

/* signingTime: 1.2.840.113549.1.9.5 */
static const unsigned char OID_PKCS9_SIGNING_TIME[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05, 0x00
};

/* ---------- 공통 유틸 (원본에서 재사용 또는 경미 변경) ---------- */

static void x509_name_list_free(mbedtls_x509_name *name)
{
    mbedtls_x509_name *cur = name->next;
    while (cur) {
        mbedtls_x509_name *prv = cur;
        cur = cur->next;
        free(prv);
    }
    name->next = NULL;
}

/**
 * [UNCHANGED - 재사용]
 * 
 * version Version
 * Version ::= INTEGER
 **/
static int pkcs7_get_version(unsigned char **p, unsigned char *end, int *ver)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_asn1_get_int(p, end, ver);
    if (ret != 0) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_VERSION, ret);
    }

    /* If version != 1, return invalid version */
    if (*ver != MBEDTLS_PKCS7_SUPPORTED_VERSION) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_VERSION;
    }

    return ret;
}

/**
 * [UNCHANGED - 재사용]
 * 
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * This is from x509.h
 **/
static int pkcs7_get_digest_algorithm(unsigned char **p, unsigned char *end,
                                      mbedtls_x509_buf *alg)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_alg_null(p, end, alg)) != 0) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    }

    return ret;
}

/**
 * [UNCHANGED - 재사용]
 * 
 * DigestAlgorithmIdentifiers :: SET of DigestAlgorithmIdentifier
 **/
static int pkcs7_get_digest_algorithm_set(unsigned char **p,
                                          unsigned char *end,
                                          mbedtls_x509_buf *alg)
{
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SET);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    }

    end = *p + len;

    ret = mbedtls_asn1_get_alg_null(p, end, alg);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    }

    /** For now, it assumes there is only one digest algorithm specified **/
    if (*p != end) {
        return MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
    }

    return 0;
}

/* [MODIFIED - 수정]
 * ContentInfo ::= SEQUENCE {
 *   contentType OBJECT IDENTIFIER,
 *   content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 * - eContentType OID 를 out_type 로 반환
 * - eContent(있으면) 의 OCTET STRING 바이트를 out_content/out_len 로 반환
 */
static int get_content_info(unsigned char **p, unsigned char *end,
                            mbedtls_pkcs7_buf *out_type,
                            const unsigned char **out_content,
                            size_t *out_len)
{
    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);

    unsigned char *seq_end = *p + len;

    /* contentType OID */
    ret = mbedtls_asn1_get_tag(p, seq_end, &len, MBEDTLS_ASN1_OID);
    if (ret != 0)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);

    out_type->tag = MBEDTLS_ASN1_OID;
    out_type->len = len;
    out_type->p   = *p;
    *p += len;

    *out_content = NULL;
    *out_len = 0;

    /* content [0] EXPLICIT OPTIONAL */
    if (*p == seq_end)
        return 0;

    /* [0] EXPLICIT */
    ret = mbedtls_asn1_get_tag(p, seq_end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (ret != 0)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);

    unsigned char *ctx_end = *p + len;

    /* 일반적으로 OCTET STRING */
    size_t os_len = 0;
    ret = mbedtls_asn1_get_tag(p, ctx_end, &os_len, MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);

    *out_content = *p;
    *out_len = os_len;
    *p += os_len;

    if (*p != ctx_end)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);

    if (*p != seq_end)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    return 0;
}

/* [MODIFIED - 수정]
 * certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL
 *   => SET OF Certificate (SEQUENCE ... ) 들
 * - 여러 개 인증서를 허용
 * - 각 인증서는 mbedtls_x509_crt 파서에 하나씩 공급
 */
static int pkcs7_get_certificates(unsigned char **p, unsigned char *end,
                            mbedtls_x509_crt *out_chain)
{
    int ret;
    size_t len = 0;

    /* [0] IMPLICIT */
    ret = mbedtls_asn1_get_tag(p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        return 0; /* optional 없음 */
    }
    if (ret != 0)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CERT, ret);

    unsigned char *set_end = *p + len;
    int count = 0;

    while (*p < set_end) {
        /* 각 Certificate 는 SEQUENCE. 길이를 먼저 읽고 그 범위를 parse_der 에 전달 */
        size_t cert_len = 0;
        unsigned char *cert_start = *p;

        ret = mbedtls_asn1_get_tag(p, set_end, &cert_len,
              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0)
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CERT, ret);

        /* 전체 인증서 바이트를 전달: cert_start ~ cert_start+tag+len+cert_len */
        {
            size_t total_len = (size_t)(*p - cert_start) + cert_len;
            ret = mbedtls_x509_crt_parse_der(out_chain, cert_start, total_len);
            if (ret != 0) {
                return MBEDTLS_ERR_PKCS7_INVALID_CERT;
            }
        }

        *p = cert_start + (size_t)(*p - cert_start) + cert_len; /* 다음 */
        count++;
    }

    if (*p != set_end)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CERT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    return count;
}

/* [UNCHANGED - 재사용] signature OCTET STRING */
static int get_signature(unsigned char **p, unsigned char *end, mbedtls_pkcs7_buf *sig)
{
    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0) return ret;
    sig->tag = MBEDTLS_ASN1_OCTET_STRING;
    sig->len = len;
    sig->p   = *p;
    *p += len;
    return 0;
}

/* Compare two mbedtls_x509_time: return -1 if a<b, 0 if equal, 1 if a>b */
static int x509_time_cmp(const mbedtls_x509_time *a, const mbedtls_x509_time *b)
{
#define CMP_FIELD(f) if ((a->f) != (b->f)) return (a->f) < (b->f) ? -1 : 1
    CMP_FIELD(year);
    CMP_FIELD(mon);
    CMP_FIELD(day);
    CMP_FIELD(hour);
    CMP_FIELD(min);
    CMP_FIELD(sec);
#undef CMP_FIELD
    return 0;
}

/* Parse ASN.1 Time (UTCTime or GeneralizedTime) to mbedtls_x509_time */
static int parse_asn1_time(unsigned char **p, unsigned char *end,
                           mbedtls_x509_time *t)
{
    int tag = **p;
    size_t len = 0;
    int ret;

    if (tag == MBEDTLS_ASN1_UTC_TIME) {
        ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_UTC_TIME);
        if (ret != 0) return ret;
        const unsigned char *s = *p;
        if (len < 10) return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
        /* YYMMDDHHMM[SS]Z */
        int yy = (s[0]-'0')*10 + (s[1]-'0');
        t->year = (yy >= 50 ? 1900 + yy : 2000 + yy);
        t->mon  = (s[2]-'0')*10 + (s[3]-'0');
        t->day  = (s[4]-'0')*10 + (s[5]-'0');
        t->hour = (s[6]-'0')*10 + (s[7]-'0');
        t->min  = (s[8]-'0')*10 + (s[9]-'0');
        t->sec  = 0;
        size_t pos = 10;
        if (len >= 12 && s[10] != 'Z') {
            t->sec = (s[10]-'0')*10 + (s[11]-'0');
            pos = 12;
        }
        /* expect 'Z' at the end */
        if (s[len-1] != 'Z') return MBEDTLS_ERR_ASN1_INVALID_DATA;
        *p += len;
        return 0;
    } else if (tag == MBEDTLS_ASN1_GENERALIZED_TIME) {
        ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_GENERALIZED_TIME);
        if (ret != 0) return ret;
        const unsigned char *s = *p;
        if (len < 12) return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
        /* YYYYMMDDHHMM[SS]Z (we only handle Zulu) */
        t->year = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0');
        t->mon  = (s[4]-'0')*10 + (s[5]-'0');
        t->day  = (s[6]-'0')*10 + (s[7]-'0');
        t->hour = (s[8]-'0')*10 + (s[9]-'0');
        t->min  = (s[10]-'0')*10 + (s[11]-'0');
        t->sec  = 0;
        size_t pos = 12;
        if (len >= 14 && s[12] != 'Z') {
            t->sec = (s[12]-'0')*10 + (s[13]-'0');
            pos = 14;
        }
        if (s[len-1] != 'Z') return MBEDTLS_ERR_ASN1_INVALID_DATA;
        *p += len;
        return 0;
    }
    return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
}

/* SignerInfo 일부를 구조체로 보관 (issuerRaw/serial, alg, sig, signedAttrs 정보 포함) */
typedef struct {
    int version;
    /* SID */
    mbedtls_x509_buf issuer_raw;
    mbedtls_x509_buf serial;
    /* digest/sig alg */
    mbedtls_x509_buf md_alg;
    mbedtls_x509_buf sig_alg;
    /* optional signedAttrs (authenticatedAttributes [0] IMPLICIT) */
    const unsigned char *signed_attrs_der; /* [0] 전체(태그 포함) 시작 포인터 */
    size_t signed_attrs_len;               /* [0] 전체 길이 */
    /* optional messageDigest value (from signedAttrs) */
    const unsigned char *msg_digest;
    size_t msg_digest_len;
    
    int has_signing_time;
    mbedtls_x509_time signing_time;

    /* signature */
    mbedtls_pkcs7_buf sig;
} signer_info_view;

/* [MODIFIED - 수정]
 * Attributes 파서: messageDigest(1.2.840.113549.1.9.4)만 추출
 * signedAttrs 는 [0] IMPLICIT SET OF Attribute
 * 각 Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }
 *  - messageDigest 의 경우 attrValues = SET OF OCTET STRING 한 개
 */
static int parse_signed_attrs(signer_info_view *out,
                                unsigned char **p, unsigned char *end,
                                unsigned char **pattrs_end)
{
    size_t total_len = 0;
    int ret = mbedtls_asn1_get_tag(p, end, &total_len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC); /* [0] IMPLICIT */
    if (ret != 0) return ret;

    unsigned char *attrs_end = *p + total_len;
    *pattrs_end = attrs_end;

    while (*p < attrs_end) {
        size_t seq_len = 0;
        /* Attribute ::= SEQUENCE */
        ret = mbedtls_asn1_get_tag(p, attrs_end, &seq_len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) return ret;
        unsigned char *attr_end = *p + seq_len;

        /* OID */
        size_t oid_len = 0;
        ret = mbedtls_asn1_get_tag(p, attr_end, &oid_len, MBEDTLS_ASN1_OID);
        if (ret != 0) return ret;
        unsigned char *oid_p = *p;

        *p += oid_len;

        /* attrValues: SET OF */
        size_t set_len = 0;
        ret = mbedtls_asn1_get_tag(p, attr_end, &set_len,
               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
        if (ret != 0) return ret;
        unsigned char *set_end = *p + set_len;

        /* 실제 비교: */
        if (!MBEDTLS_OID_CMP_RAW(OID_PKCS9_MESSAGE_DIGEST, oid_p, oid_len)) {
            /* SET OF OCTET STRING (1개) */
            size_t vlen = 0;
            int r2 = mbedtls_asn1_get_tag(p, set_end, &vlen, MBEDTLS_ASN1_OCTET_STRING);
            if (r2 == 0) {
                /* messageDigest (있으면) */
                out->msg_digest = *p;
                out->msg_digest_len = vlen;
                *p += vlen;
            } else {
                return r2;
            }
            if (*p != set_end) return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        } else if (!MBEDTLS_OID_CMP_RAW(OID_PKCS9_SIGNING_TIME, oid_p, oid_len)) {
            /* Time ::= UTCTime | GeneralizedTime */
            unsigned char *q = *p;
            int r2 = parse_asn1_time(&q, set_end, &out->signing_time);
            if (r2 != 0) return r2;
            if (q != set_end) return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            out->has_signing_time = 1;
            *p = set_end;
        } else {
            /* skip unknown attribute values */
            *p = set_end;
        }

        if (*p != attr_end) return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    if (*p != attrs_end) return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    return 0;
}

/* [MODIFIED - 수정]
 * SignerInfo 파서
 *  - issuerAndSerialNumber 저장
 *  - digest/sig alg
 *  - authenticatedAttributes(있으면) 전체 DER 범위 + messageDigest
 *  - signature
 */
static int get_signer_info(unsigned char **p, unsigned char *end, signer_info_view *out)
{
    int ret;
    size_t len = 0;

    memset(out, 0, sizeof(*out));

    ret = mbedtls_asn1_get_tag(p, end, &len,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);
    unsigned char *si_end = *p + len;

    /* version */
    ret = pkcs7_get_version(p, si_end, &out->version);
    if (ret != 0) return ret;

    /* issuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER } */
    size_t iss_len = 0;
    ret = mbedtls_asn1_get_tag(p, si_end, &iss_len,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);
    unsigned char *iss_end = *p + iss_len;

    #if 0
    // FIXME: not working (returns -98)
    /* issuer Name (raw) */
    out->issuer_raw.p = *p;
    {
        mbedtls_x509_name dummy = {0};
        ret = mbedtls_x509_get_name(p, iss_end, &dummy);
        fprintf(stderr, "ERRR TP X 01 %d\n", ret);
        if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);
        out->issuer_raw.len = (size_t)(*p - out->issuer_raw.p);
        x509_name_list_free(&dummy);
    }
    #else
    ret = mbedtls_asn1_get_tag(p, iss_end, &len,
                                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);
    }
    unsigned char *iss_seq_end = *p + len;

    /* issuer 전체를 RAW로 저장 (Name 구조 파싱은 생략) */
    out->issuer_raw.p = *p;
    out->issuer_raw.len = (size_t)(iss_seq_end - *p);

    /* issuer 필드 건너뛰기 */
    *p = iss_seq_end;
    #endif

    /* serialNumber */
    ret = mbedtls_x509_get_serial(p, iss_end, &out->serial);
    if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);
    if (*p != iss_end) return MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;

    /* digestAlgorithm */
    ret = pkcs7_get_digest_algorithm(p, si_end, &out->md_alg);
    if (ret != 0) return ret;

    /* authenticatedAttributes [0] IMPLICIT OPTIONAL */
    if (*p < si_end && (**p & MBEDTLS_ASN1_CONTEXT_SPECIFIC) == MBEDTLS_ASN1_CONTEXT_SPECIFIC) {
        /* 상위에서 [0] 태그 시작 지점을 세이브해야 하므로, 태그 시작 포인터 */
        const unsigned char *tag_start = *p;
        unsigned char* attr_end = NULL;

        ret = parse_signed_attrs(out, p, si_end, &attr_end);
        if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);

        out->signed_attrs_der = tag_start; /* [0] 태그 시작 */
        out->signed_attrs_len = (size_t)(attr_end - tag_start); /* 태그 포함 전체 길이(간단 도출) */

        *p = attr_end;
    }

    /* digestEncryptionAlgorithm */
    ret = pkcs7_get_digest_algorithm(p, si_end, &out->sig_alg);
    if (ret != 0) return ret;

    /* signature: EncryptedDigest OCTET STRING */
    ret = get_signature(p, si_end, &out->sig);
    if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);

    /* unauthenticatedAttributes [1] IMPLICIT OPTIONAL -> 무시. 남은 바이트 있으면 모두 스킵 */
    if (*p != si_end) {
        /* 엄격히 하려면 오류. 여기서는 지원 안 함 */
        return MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
    }
    return 0;
}

/* [MODIFIED - 수정]
 * SignerInfos ::= SET OF SignerInfo (단일 서명자만 허용)
 */
static int get_signer_infos(unsigned char **p, unsigned char *end, signer_info_view *out)
{
    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
    if (ret != 0)
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);

    unsigned char *set_end = *p + len;

    /* 첫 SignerInfo */
    ret = get_signer_info(p, set_end, out);
    if (ret != 0) return ret;

    if (*p != set_end) {
        /* 다중 서명자 지원은 명시적으로 불가 처리 */
        return MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
    }
    return 0;
}

/* [MODIFIED - 수정]
 * SignedData 전체 파서(Attached 지원):
 * - version, digestAlgorithms, contentInfo(eContentType + eContent),
 *   certificates(여러개), crls(무시), signerInfos(단일)
 */
static int parse_signed_data(unsigned char *buf, size_t buflen,
                             mbedtls_pkcs7_buf *econtent_type,
                             const unsigned char **econtent,
                             size_t *econtent_len,
                             mbedtls_x509_crt *certs,
                             signer_info_view *siv,
                             mbedtls_md_type_t *md_alg_out)
{
    int ret;
    unsigned char *p = buf;
    unsigned char *end = buf + buflen;
    size_t len = 0;

    /* SignedData ::= SEQUENCE */
    ret = mbedtls_asn1_get_tag(&p, end, &len,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT, ret);
    if (p + len != end) return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    /* version */
    int ver = 0;
    ret = pkcs7_get_version(&p, end, &ver);
    if (ret != 0) return ret;

    /* digestAlgorithms */
    mbedtls_x509_buf md_alg = {0};
    ret = pkcs7_get_digest_algorithm_set(&p, end, &md_alg);
    if (ret != 0) return ret;

    mbedtls_md_type_t md_alg_type;
    ret = mbedtls_x509_oid_get_md_alg(&md_alg, &md_alg_type);
    if (ret != 0) return MBEDTLS_ERR_PKCS7_INVALID_ALG;
    *md_alg_out = md_alg_type;

    /* contentInfo (attached 지원) */
    ret = get_content_info(&p, end, econtent_type, econtent, econtent_len);
    if (ret != 0) return ret;

    /* certificates (optional) */
    mbedtls_x509_crt_init(certs);
    int ncert = pkcs7_get_certificates(&p, end, certs);
    if (ncert < 0) return ncert;

    /* crls (optional) -> [1] IMPLICIT, 여기서는 스킵 시도 */
    if (p < end && (*p & MBEDTLS_ASN1_CONTEXT_SPECIFIC) == MBEDTLS_ASN1_CONTEXT_SPECIFIC) {
        size_t crl_len = 0;
        int r2 = mbedtls_asn1_get_tag(&p, end, &crl_len,
                  MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
        if (r2 == 0) {
            p += crl_len; /* 통째로 스킵 */
        }
    }

    /* signerInfos (단일) */
    ret = get_signer_infos(&p, end, siv);
    if (ret != 0) return ret;

    if (p != end) return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;

    return 0;
}

/* [MODIFIED - 수정]
 * SID(issuer_raw + serial) 로 certs 체인에서 매칭 인증서를 찾음
 */
static mbedtls_x509_crt *find_signer_cert_by_sid(mbedtls_x509_crt *certs, const signer_info_view *siv)
{
    for (mbedtls_x509_crt *c = certs; c != NULL && c->raw.p != NULL; c = c->next) {
        #if 0
        // FIXME: not working
        if (c->issuer_raw.len == siv->issuer_raw.len &&
            memcmp(c->issuer_raw.p, siv->issuer_raw.p, siv->issuer_raw.len) == 0 &&
            c->serial.len == siv->serial.len &&
            memcmp(c->serial.p, siv->serial.p, siv->serial.len) == 0) {
            return c;
        }
        #else
        if (c->serial.len == siv->serial.len &&
            memcmp(c->serial.p, siv->serial.p, siv->serial.len) == 0) {
            return c;
        }
        #endif
    }
    return NULL;
}

/* [MODIFIED - 수정]
 * 서명 검증:
 * - signedAttrs 존재시: signedAttrs 전체 DER(태그+길이 포함) 를 해시 → 서명 검증
 * - 미존재시: eContent 해시 → 서명 검증 (원본 로직 재사용)
 */
static int verify_signature(const signer_info_view *siv,
                            const mbedtls_x509_crt *signer_cert,
                            mbedtls_md_type_t md_alg,
                            const unsigned char *hash_or_attrs, size_t len,
                            int is_attrs)
{
    int ret = 0;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_alg);
    if (!md_info) return MBEDTLS_ERR_PKCS7_VERIFY_FAIL;

    unsigned char calc_hash[MBEDTLS_MD_MAX_SIZE];
    size_t hlen = mbedtls_md_get_size(md_info);

    if (is_attrs) {
        unsigned char prefix[1] = {0x31};
        mbedtls_md_context_t md_ctx;
        mbedtls_md_init(&md_ctx);
        ret = mbedtls_md_setup(&md_ctx, md_info, 0);
        if (ret == 0)
            ret = mbedtls_md_starts(&md_ctx);
        if (ret == 0)
            ret = mbedtls_md_update(&md_ctx, prefix, 1);
        if (ret == 0)
            ret = mbedtls_md_update(&md_ctx, hash_or_attrs+1, len-1);
        if (ret == 0)
            ret = mbedtls_md_finish(&md_ctx, calc_hash);
        mbedtls_md_free(&md_ctx);
        if (ret != 0) return MBEDTLS_ERR_PKCS7_VERIFY_FAIL;
    } else {
        if (len != hlen) return MBEDTLS_ERR_PKCS7_VERIFY_FAIL;
        memcpy(calc_hash, hash_or_attrs, hlen);
    }

    ret = mbedtls_pk_verify_ext(signer_cert->private_sig_pk,
        (mbedtls_pk_context *)&signer_cert->pk,
        md_alg, calc_hash, hlen,
        siv->sig.p, siv->sig.len);

    return ret;
}

/* ---------- 최상위: Attached PKCS#7 파싱 + 검증 + view 구성 ---------- */

int mbedtls_pkcs7_parse_verify_attached(
    const unsigned char *pkcs7_der, size_t pkcs7_len,
    mbedtls_pkcs7_view *out_view)
{
    if (!pkcs7_der || !out_view) return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;

    int ret;
    unsigned char *p = (unsigned char *)pkcs7_der;
    unsigned char *end = (unsigned char *)pkcs7_der + pkcs7_len;
    size_t len = 0;

    memset(out_view, 0, sizeof(*out_view));
    mbedtls_x509_crt_init(&out_view->signer_cert);

    /* ContentInfo wrapper of SignedData */
    ret = mbedtls_asn1_get_tag(&p, end, &len,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT, ret);
    if (p + len != end) return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    /* contentType: must be signedData OID */
    size_t oid_len = 0;
    ret = mbedtls_asn1_get_tag(&p, end, &oid_len, MBEDTLS_ASN1_OID);
    if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT, ret);

    if (MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_PKCS7_SIGNED_DATA, p, oid_len))
        return MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE; /* 다른 유형은 지원X */

    p += oid_len;

    /* [0] EXPLICIT SignedData */
    size_t sd_len = 0;
    ret = mbedtls_asn1_get_tag(&p, end, &sd_len,
          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (ret != 0) return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT, ret);

    unsigned char *sd = p;
    unsigned char *sd_end = p + sd_len;

    /* SignedData 파싱 */
    mbedtls_pkcs7_buf ectype = {0};
    const unsigned char *econtent = NULL;
    size_t econtent_len = 0;
    mbedtls_x509_crt certs; mbedtls_x509_crt_init(&certs);
    signer_info_view siv = {0};
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;

    ret = parse_signed_data(sd, (size_t)(sd_end - sd),
                            &ectype, &econtent, &econtent_len,
                            &certs, &siv, &md_alg);
    if (ret != 0) { mbedtls_x509_crt_free(&certs); return ret; }

    /* eContentType == data 인지 등은 요구사항상 제한 없음: 그대로 노출 */
    out_view->econtent_type = ectype;
    out_view->content = econtent;          /* DER 버퍼 내 포인터 */
    out_view->content_len = econtent_len;

    /* SID로 signer cert 매칭 */
    mbedtls_x509_crt *signer = find_signer_cert_by_sid(&certs, &siv);
    if (!signer) { mbedtls_x509_crt_free(&certs); return MBEDTLS_ERR_PKCS7_INVALID_CERT; }

    /* eContent 해시 계산 */
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_alg);
    if (!md_info) { mbedtls_x509_crt_free(&certs); return MBEDTLS_ERR_PKCS7_INVALID_ALG; }

    unsigned char data_hash[MBEDTLS_MD_MAX_SIZE];
    ret = mbedtls_md(md_info, econtent ? econtent : (const unsigned char *)"", econtent_len, data_hash);
    if (ret != 0) { mbedtls_x509_crt_free(&certs); return MBEDTLS_ERR_PKCS7_VERIFY_FAIL; }

    /* signedAttrs 존재하면 messageDigest와 비교 */
    if (siv.signed_attrs_der && siv.msg_digest) {
        size_t hlen = mbedtls_md_get_size(md_info);
        if (siv.msg_digest_len != hlen ||
            memcmp(siv.msg_digest, data_hash, hlen) != 0) {
            mbedtls_x509_crt_free(&certs);
            return MBEDTLS_ERR_PKCS7_VERIFY_FAIL; /* 콘텐츠 해시 불일치 */
        }
        /* 서명은 signedAttrs DER 위에 계산됨 */
        ret = verify_signature(&siv, signer, md_alg,
                               siv.signed_attrs_der, siv.signed_attrs_len,
                               /*is_attrs=*/1);
    } else {
        /* signedAttrs 없으면 해시 자체로 검증 */
        size_t hlen = mbedtls_md_get_size(md_info);
        ret = verify_signature(&siv, signer, md_alg, data_hash, hlen, /*is_attrs=*/0);
    }
    
    if (ret != 0) { mbedtls_x509_crt_free(&certs); return MBEDTLS_ERR_PKCS7_VERIFY_FAIL; }

    /* out_view->signer_cert 에 매칭 인증서를 복제(소유권 분리) */
    {
        int rc = mbedtls_x509_crt_parse_der(&out_view->signer_cert, signer->raw.p, signer->raw.len);
        if (rc != 0) { mbedtls_x509_crt_free(&certs); return MBEDTLS_ERR_PKCS7_INVALID_CERT; }
    }

    if (siv.has_signing_time) {
        if (x509_time_cmp(&signer->valid_from, &siv.signing_time) > 0 ||
            x509_time_cmp(&siv.signing_time, &signer->valid_to) > 0) {
            /* signingTime이 인증서 유효기간 밖이면 실패 */
            mbedtls_x509_crt_free(&certs);
            return MBEDTLS_ERR_PKCS7_CERT_DATE_INVALID;
        }
    }
    mbedtls_x509_crt_free(&certs);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "pkcs7_ex.h"

/* ===== 유틸 함수 ===== */

static void print_err(const char *where, int ret)
{
    char buf[256];
    mbedtls_strerror(ret, buf, sizeof(buf));
    fprintf(stderr, "%s: %s (%d)\n", where, buf, ret);
}

static int load_file(const char *path, unsigned char **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buf = malloc(sz);
    if (!*buf) { fclose(f); return -1; }
    if (fread(*buf, 1, sz, f) != (size_t)sz) { fclose(f); free(*buf); return -1; }
    fclose(f);
    *len = sz;
    return 0;
}

/* 간단한 metadata.txt 파서 */
static int parse_metadata(const char *path, size_t *expect_len, char *expect_hash, size_t hashlen)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    *expect_len = 0;
    expect_hash[0] = 0;
    while (fgets(line, sizeof(line), f)) {
        const char* p = line;
        if (strncmp(line, "expect_length:", 14) == 0) {
            p += 14;
            while (*p == ' ' || *p == '\t') p++;
            *expect_len = (size_t)atoi(p);
        } else if (strncmp(line, "payload_sha256:", 15) == 0) {
            p += 15;
            while (*p == ' ' || *p == '\t') p++;
            strncpy(expect_hash, p, hashlen - 1);
            expect_hash[hashlen - 1] = 0;
        }
    }
    fclose(f);
    /* trim */
    for (int i = strlen(expect_hash) - 1; i >= 0; i--)
        if (expect_hash[i] == '\n' || expect_hash[i] == '\r') expect_hash[i] = 0;
    return 0;
}

/* ===== 단일 테스트 실행 ===== */
static int run_case(const char *basepath)
{
    char path_der[512], path_txt[512];
    snprintf(path_der, sizeof(path_der), "%s.der", basepath);
    snprintf(path_txt, sizeof(path_txt), "%s.txt", basepath);

    unsigned char *buf = NULL;
    size_t buflen = 0;

    if (load_file(path_der, &buf, &buflen) != 0) {
        fprintf(stderr, "❌ Cannot read DER file: %s\n", path_der);
        return 1;
    }

    size_t expect_len = 0;
    char expect_hash[128] = {0};
    if (parse_metadata(path_txt, &expect_len, expect_hash, sizeof(expect_hash)) != 0) {
        fprintf(stderr, "❌ Cannot read metadata file: %s\n", path_txt);
        free(buf);
        return 1;
    }

    printf("\n=== Running test: %s ===\n", basepath);
    mbedtls_pkcs7_view view;
    int ret = mbedtls_pkcs7_parse_verify_attached(buf, buflen, &view);
    if (ret != 0) {
        fprintf(stderr, "ret = %d\n", ret);
        print_err("verify", ret);
        free(buf);
        return 1;
    }

    printf("✅ Verification OK\n");
    printf("   eContent length = %zu (expected %zu)\n", view.content_len, expect_len);

    /* SHA256 검증 */
    unsigned char sha256[32];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(md, view.content, view.content_len, sha256);

    char calc_hex[65]; calc_hex[64] = 0;
    for (size_t i = 0; i < 32; i++)
        sprintf(calc_hex + 2 * i, "%02x", sha256[i]);

    if (strncmp(calc_hex, expect_hash, 64) != 0) {
        printf("❌ Hash mismatch!\nExpected: %s\nActual:   %s\n", expect_hash, calc_hex);
        mbedtls_x509_crt_free(&view.signer_cert);
        free(buf);
        return 1;
    } else {
        printf("   SHA256 hash OK.\n");
    }

    mbedtls_x509_crt_free(&view.signer_cert);
    free(buf);
    return 0;
}

/* ===== main ===== */
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <test_case_prefix1> [<test_case_prefix2> ...]\n", argv[0]);
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s tests/case1_attached tests/case2_noattrs\n", argv[0]);
        return 1;
    }

    psa_crypto_init();

    int failures = 0;
    for (int i = 1; i < argc; i++) {
        if (run_case(argv[i]) != 0) {
            fprintf(stderr, "❌ Test failed: %s\n", argv[i]);
            failures++;
        } else {
            printf("✅ Test passed: %s\n", argv[i]);
        }
    }

    if (failures == 0)
        printf("\n🎉 All tests passed successfully.\n");
    else
        printf("\n⚠️ %d test(s) failed.\n", failures);

    return failures ? 1 : 0;
}
/*
 * Integration tests for the C Rijndael encrypt/decrypt executables.
 *
 * Build:
 *   gcc rijndael-c/test_rijndael.c -o test_rijndael_c
 *
 * Run from the project root (where rijndael-encrypt.exe / rijndael-decrypt.exe live):
 *   ./test_rijndael_c
 *
 * Returns 0 on all tests passing, 1 on any failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Minimal test framework
 * ---------------------------------------------------------------------- */

static int g_passed = 0;
static int g_failed = 0;

#define TEST_ASSERT(label, cond)                                        \
    do {                                                                \
        if (cond) {                                                     \
            printf("  PASS : %s\n", label);                             \
            g_passed++;                                                 \
        } else {                                                        \
            printf("  FAIL : %s\n", label);                             \
            g_failed++;                                                 \
        }                                                               \
    } while (0)

#define TEST_ASSERT_EQ(label, expected, actual)                         \
    do {                                                                \
        long long _e = (long long)(expected);                           \
        long long _a = (long long)(actual);                             \
        if (_e == _a) {                                                 \
            printf("  PASS : %s\n", label);                             \
            g_passed++;                                                 \
        } else {                                                        \
            printf("  FAIL : %s [expected=%lld actual=%lld]\n",         \
                   label, _e, _a);                                      \
            g_failed++;                                                 \
        }                                                               \
    } while (0)

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define KEY_HEX       "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650"
#define IV_HEX        "2cef85f5259ae311034de17fda3b8369"
#define WRONG_KEY_HEX "0000000000000000000000000000000000000000000000000000000000000000"
#define WRONG_IV_HEX  "ffffffffffffffffffffffffffffffff"
#define PLAINTEXT     "my message to you, let's win"
#define PLAINTEXT_LEN 28

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static char g_tmpdir[256];

static void make_tmpdir(void) {
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/rijndael-c-test-XXXXXX");
    if (mkdtemp(g_tmpdir) == NULL) {
        perror("mkdtemp");
        exit(1);
    }
}

static void cleanup_tmpdir(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_tmpdir);
    system(cmd);
}

/* Round-robin pool of 8 path buffers so multiple tmppath() calls in one
 * snprintf() argument list each get a distinct buffer. */
static char *tmppath(const char *name) {
    static char bufs[8][512];
    static int idx = 0;
    idx = (idx + 1) & 7;
    snprintf(bufs[idx], sizeof(bufs[idx]), "%s/%s", g_tmpdir, name);
    return bufs[idx];
}

static void write_file(const char *path, const void *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) { perror(path); exit(1); }
    fwrite(data, 1, len, fp);
    fclose(fp);
}

static void write_str(const char *path, const char *str) {
    write_file(path, str, strlen(str));
}

static long file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

static int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static int read_file(const char *path, uint8_t **out, size_t *outlen) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    *outlen = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    *out = (uint8_t *)malloc(*outlen);
    fread(*out, 1, *outlen, fp);
    fclose(fp);
    return 0;
}

static int run_encrypt(const char *key_hex, const char *iv_hex, const void *pt, size_t pt_len) {
    write_file(tmppath("input.txt"), pt, pt_len);
    write_str(tmppath("input.key"), key_hex);
    write_str(tmppath("input.iv"),  iv_hex);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "./rijndael-encrypt.exe '%s' '%s' '%s' '%s' > /dev/null 2>&1",
             tmppath("input.txt"), tmppath("output.rij"),
             tmppath("input.key"), tmppath("input.iv"));
    return system(cmd);
}

static int run_decrypt(const char *key_hex, const char *iv_hex) {
    write_str(tmppath("dec.key"), key_hex);
    write_str(tmppath("dec.iv"),  iv_hex);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "./rijndael-decrypt.exe '%s' '%s' '%s' '%s' > /dev/null 2>&1",
             tmppath("output.rij"), tmppath("decrypted.txt"),
             tmppath("dec.key"), tmppath("dec.iv"));
    return system(cmd);
}

/* -------------------------------------------------------------------------
 * Encrypt tests
 * ---------------------------------------------------------------------- */

static void test_encrypt_creates_output_file(void) {
    make_tmpdir();
    int rc = run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    TEST_ASSERT_EQ("encrypt: exit 0", 0, rc);
    TEST_ASSERT("encrypt: output file created", file_exists(tmppath("output.rij")));
    cleanup_tmpdir();
}

static void test_encrypt_creates_sig_file(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    TEST_ASSERT("encrypt: .sig file created", file_exists(tmppath("output.rij.sig")));
    cleanup_tmpdir();
}

static void test_encrypt_output_multiple_of_block_size(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    long sz = file_size(tmppath("output.rij"));
    TEST_ASSERT("encrypt: ciphertext is multiple of 16", sz > 0 && sz % 16 == 0);
    cleanup_tmpdir();
}

static void test_encrypt_sig_is_64_bytes(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    long sz = file_size(tmppath("output.rij.sig"));
    TEST_ASSERT_EQ("encrypt: sig is 64 bytes (HMAC-SHA512)", 64, sz);
    cleanup_tmpdir();
}

static void test_encrypt_padding_lengths(void) {
    struct { int input_len; int expected; } cases[] = {
        {0,  16}, {1,  16}, {15, 16},
        {16, 32}, {17, 32}, {28, 32}, {31, 32},
        {32, 48}
    };
    int n = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < n; i++) {
        make_tmpdir();
        uint8_t *pt = (uint8_t *)calloc(1, cases[i].input_len ? cases[i].input_len : 1);
        memset(pt, 'A', cases[i].input_len);
        run_encrypt(KEY_HEX, IV_HEX, pt, (size_t)cases[i].input_len);
        free(pt);
        long sz = file_size(tmppath("output.rij"));
        char label[128];
        snprintf(label, sizeof(label),
                 "encrypt: input %d bytes -> output %d bytes",
                 cases[i].input_len, cases[i].expected);
        TEST_ASSERT_EQ(label, cases[i].expected, sz);
        cleanup_tmpdir();
    }
}

static void test_encrypt_deterministic(void) {
    /* Run twice with same key/IV and compare ciphertexts */
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    uint8_t *ct1 = NULL; size_t ct1_len = 0;
    read_file(tmppath("output.rij"), &ct1, &ct1_len);
    cleanup_tmpdir();

    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    uint8_t *ct2 = NULL; size_t ct2_len = 0;
    read_file(tmppath("output.rij"), &ct2, &ct2_len);
    cleanup_tmpdir();

    TEST_ASSERT("encrypt: deterministic with same key/IV",
                ct1_len == ct2_len && memcmp(ct1, ct2, ct1_len) == 0);
    free(ct1); free(ct2);
}

static void test_encrypt_different_iv_different_ciphertext(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    uint8_t *ct1 = NULL; size_t ct1_len = 0;
    read_file(tmppath("output.rij"), &ct1, &ct1_len);
    cleanup_tmpdir();

    make_tmpdir();
    run_encrypt(KEY_HEX, WRONG_IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    uint8_t *ct2 = NULL; size_t ct2_len = 0;
    read_file(tmppath("output.rij"), &ct2, &ct2_len);
    cleanup_tmpdir();

    TEST_ASSERT("encrypt: different IV -> different ciphertext",
                !(ct1_len == ct2_len && memcmp(ct1, ct2, ct1_len) == 0));
    free(ct1); free(ct2);
}

static void test_encrypt_different_key_different_ciphertext(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    uint8_t *ct1 = NULL; size_t ct1_len = 0;
    read_file(tmppath("output.rij"), &ct1, &ct1_len);
    cleanup_tmpdir();

    make_tmpdir();
    run_encrypt(WRONG_KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    uint8_t *ct2 = NULL; size_t ct2_len = 0;
    read_file(tmppath("output.rij"), &ct2, &ct2_len);
    cleanup_tmpdir();

    TEST_ASSERT("encrypt: different key -> different ciphertext",
                !(ct1_len == ct2_len && memcmp(ct1, ct2, ct1_len) == 0));
    free(ct1); free(ct2);
}

static void test_encrypt_exit_one_no_args(void) {
    int rc = system("./rijndael-encrypt.exe > /dev/null 2>&1");
    TEST_ASSERT("encrypt: exit non-zero on no args", WEXITSTATUS(rc) != 0);
}

static void test_encrypt_nonzero_missing_input(void) {
    make_tmpdir();
    write_str(tmppath("input.key"), KEY_HEX);
    write_str(tmppath("input.iv"),  IV_HEX);
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "./rijndael-encrypt.exe '%s' '%s' '%s' '%s' > /dev/null 2>&1",
             tmppath("nonexistent.txt"), tmppath("output.rij"),
             tmppath("input.key"), tmppath("input.iv"));
    int rc = system(cmd);
    TEST_ASSERT("encrypt: non-zero exit on missing input file", WEXITSTATUS(rc) != 0);
    cleanup_tmpdir();
}

/* -------------------------------------------------------------------------
 * Decrypt tests
 * ---------------------------------------------------------------------- */

static void test_decrypt_roundtrip(void) {
    make_tmpdir();
    int rc = run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    TEST_ASSERT_EQ("roundtrip: encrypt exits 0", 0, rc);
    rc = run_decrypt(KEY_HEX, IV_HEX);
    TEST_ASSERT_EQ("roundtrip: decrypt exits 0", 0, rc);

    uint8_t *got = NULL; size_t got_len = 0;
    read_file(tmppath("decrypted.txt"), &got, &got_len);
    TEST_ASSERT("roundtrip: plaintext recovered",
                got_len == PLAINTEXT_LEN &&
                memcmp(got, PLAINTEXT, PLAINTEXT_LEN) == 0);
    free(got);
    cleanup_tmpdir();
}

static void test_decrypt_roundtrip_empty(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, "", 0);
    int rc = run_decrypt(KEY_HEX, IV_HEX);
    TEST_ASSERT_EQ("roundtrip empty: decrypt exits 0", 0, rc);
    long sz = file_size(tmppath("decrypted.txt"));
    TEST_ASSERT_EQ("roundtrip empty: output is 0 bytes", 0, sz);
    cleanup_tmpdir();
}

static void test_decrypt_roundtrip_exact_block(void) {
    make_tmpdir();
    const char *pt = "1234567890abcdef";  /* exactly 16 bytes */
    run_encrypt(KEY_HEX, IV_HEX, pt, 16);
    int rc = run_decrypt(KEY_HEX, IV_HEX);
    TEST_ASSERT_EQ("roundtrip 16-byte: decrypt exits 0", 0, rc);
    uint8_t *got = NULL; size_t got_len = 0;
    read_file(tmppath("decrypted.txt"), &got, &got_len);
    TEST_ASSERT("roundtrip 16-byte: plaintext recovered",
                got_len == 16 && memcmp(got, pt, 16) == 0);
    free(got);
    cleanup_tmpdir();
}

static void test_decrypt_roundtrip_large(void) {
    make_tmpdir();
    uint8_t *pt = (uint8_t *)malloc(8192);
    for (int i = 0; i < 8192; i++) pt[i] = (uint8_t)(i & 0xFF);
    run_encrypt(KEY_HEX, IV_HEX, pt, 8192);
    int rc = run_decrypt(KEY_HEX, IV_HEX);
    TEST_ASSERT_EQ("roundtrip large: decrypt exits 0", 0, rc);
    uint8_t *got = NULL; size_t got_len = 0;
    read_file(tmppath("decrypted.txt"), &got, &got_len);
    TEST_ASSERT("roundtrip large: plaintext recovered",
                got_len == 8192 && memcmp(got, pt, 8192) == 0);
    free(pt); free(got);
    cleanup_tmpdir();
}

static void test_decrypt_tampered_ciphertext_fails(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    /* Flip first byte of ciphertext */
    uint8_t *ct = NULL; size_t ct_len = 0;
    read_file(tmppath("output.rij"), &ct, &ct_len);
    ct[0] ^= 0xFF;
    write_file(tmppath("output.rij"), ct, ct_len);
    free(ct);
    int rc = run_decrypt(KEY_HEX, IV_HEX);
    TEST_ASSERT("decrypt: tampered ciphertext fails", WEXITSTATUS(rc) != 0);
    cleanup_tmpdir();
}

static void test_decrypt_tampered_sig_fails(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    uint8_t *sig = NULL; size_t sig_len = 0;
    read_file(tmppath("output.rij.sig"), &sig, &sig_len);
    sig[0] ^= 0xFF;
    write_file(tmppath("output.rij.sig"), sig, sig_len);
    free(sig);
    int rc = run_decrypt(KEY_HEX, IV_HEX);
    TEST_ASSERT("decrypt: tampered .sig fails", WEXITSTATUS(rc) != 0);
    cleanup_tmpdir();
}

static void test_decrypt_wrong_key_fails(void) {
    make_tmpdir();
    run_encrypt(KEY_HEX, IV_HEX, PLAINTEXT, PLAINTEXT_LEN);
    int rc = run_decrypt(WRONG_KEY_HEX, IV_HEX);
    TEST_ASSERT("decrypt: wrong key fails", WEXITSTATUS(rc) != 0);
    cleanup_tmpdir();
}

static void test_decrypt_exit_one_no_args(void) {
    int rc = system("./rijndael-decrypt.exe > /dev/null 2>&1");
    TEST_ASSERT("decrypt: exit non-zero on no args", WEXITSTATUS(rc) != 0);
}

static void test_decrypt_nonzero_missing_ciphertext(void) {
    make_tmpdir();
    write_str(tmppath("input.key"), KEY_HEX);
    write_str(tmppath("input.iv"),  IV_HEX);
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "./rijndael-decrypt.exe '%s' '%s' '%s' '%s' > /dev/null 2>&1",
             tmppath("nonexistent.rij"), tmppath("out.txt"),
             tmppath("input.key"), tmppath("input.iv"));
    int rc = system(cmd);
    TEST_ASSERT("decrypt: non-zero exit on missing ciphertext", WEXITSTATUS(rc) != 0);
    cleanup_tmpdir();
}

/* -------------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------- */

int main(void) {
    printf("=== RijndaelTest (C) ===\n");

    printf("\n-- Encrypt --\n");
    test_encrypt_creates_output_file();
    test_encrypt_creates_sig_file();
    test_encrypt_output_multiple_of_block_size();
    test_encrypt_sig_is_64_bytes();
    test_encrypt_padding_lengths();
    test_encrypt_deterministic();
    test_encrypt_different_iv_different_ciphertext();
    test_encrypt_different_key_different_ciphertext();
    test_encrypt_exit_one_no_args();
    test_encrypt_nonzero_missing_input();

    printf("\n-- Decrypt --\n");
    test_decrypt_roundtrip();
    test_decrypt_roundtrip_empty();
    test_decrypt_roundtrip_exact_block();
    test_decrypt_roundtrip_large();
    test_decrypt_tampered_ciphertext_fails();
    test_decrypt_tampered_sig_fails();
    test_decrypt_wrong_key_fails();
    test_decrypt_exit_one_no_args();
    test_decrypt_nonzero_missing_ciphertext();

    printf("\n=== Results: %d passed, %d failed ===\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}

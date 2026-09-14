/*
 * Task 7: Brute-Force Secret Key from Dictionary
 * Uses OpenSSL EVP crypto library to brute-force AES-128-CBC key.
 *
 * Given:
 *   Plaintext:  "This is a top secret." (21 bytes)
 *   Ciphertext: 764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2
 *   IV:         aabbccddeeff00998877665544332211
 *   Key:        English word padded with '#' (0x23) to 16 bytes
 *
 * Compile: gcc -o task7 task7_brute_force.c -lcrypto
 * Run:     task7.exe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define KEY_LEN      16
#define BLOCK_LEN    16
#define MAX_WORD_LEN 128
#define WORDS_FILE   "..\\Labsetup\\Files\\words.txt"

/* Expected ciphertext (hex) */
static const unsigned char EXPECTED_CT[] = {
    0x76, 0x4a, 0xa2, 0x6b, 0x55, 0xa4, 0xda, 0x65,
    0x4d, 0xf6, 0xb1, 0x9e, 0x4b, 0xce, 0x00, 0xf4,
    0xed, 0x05, 0xe0, 0x93, 0x46, 0xfb, 0x0e, 0x76,
    0x25, 0x83, 0xcb, 0x7d, 0xa2, 0xac, 0x93, 0xa2
};
#define CT_LEN 32

/* Known plaintext */
static const unsigned char PLAINTEXT[] = "This is a top secret.";
#define PT_LEN 21

/* IV (hex) */
static const unsigned char IV[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
};

/*
 * Pad a word with '#' to 16 bytes for AES-128 key.
 * Returns length of key written.
 */
static int make_key(const char *word, unsigned char *key) {
    int len = (int)strlen(word);
    int i;
    memset(key, '#', KEY_LEN);
    for (i = 0; i < len && i < KEY_LEN; i++) {
        key[i] = (unsigned char)word[i];
    }
    return KEY_LEN;
}

/*
 * AES-128-CBC encrypt with PKCS#7 padding using EVP interface.
 * Returns ciphertext length, or -1 on error.
 */
static int aes_cbc_encrypt(const unsigned char *key, const unsigned char *iv,
                           const unsigned char *pt, int pt_len,
                           unsigned char *ct, int ct_max) {
    EVP_CIPHER_CTX *ctx;
    int len = 0, ct_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

/*
 * AES-128-CBC decrypt with PKCS#7 padding removal using EVP interface.
 * Returns plaintext length, or -1 on error.
 */
static int aes_cbc_decrypt(const unsigned char *key, const unsigned char *iv,
                           const unsigned char *ct, int ct_len,
                           unsigned char *pt, int pt_max) {
    EVP_CIPHER_CTX *ctx;
    int len = 0, pt_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    pt_len = len;

    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    pt_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return pt_len;
}

int main(void) {
    FILE *fp;
    char word[MAX_WORD_LEN];
    unsigned char key[KEY_LEN];
    unsigned char decrypted[256];
    int dec_len;
    int attempt = 0;
    int found = 0;
    clock_t start, end;
    double elapsed;

    printf("============================================================\n");
    printf("TASK 7: BRUTE-FORCE SECRET KEY (C - OpenSSL EVP Library)\n");
    printf("============================================================\n\n");

    printf("Given:\n");
    printf("  Plaintext:  %s\n", PLAINTEXT);
    printf("  Ciphertext: ");
    for (int i = 0; i < CT_LEN; i++) printf("%02x", EXPECTED_CT[i]);
    printf("\n  IV:         ");
    for (int i = 0; i < BLOCK_LEN; i++) printf("%02x", IV[i]);
    printf("\n  Key format: English word + '#' padding to 16 bytes\n");

    printf("\nDictionary: %s\n", WORDS_FILE);
    printf("Brute-forcing...\n");

    start = clock();

    fp = fopen(WORDS_FILE, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s\n", WORDS_FILE);
        return 1;
    }

    while (fgets(word, sizeof(word), fp)) {
        /* Remove trailing newline */
        int wlen = (int)strlen(word);
        while (wlen > 0 && (word[wlen-1] == '\n' || word[wlen-1] == '\r'))
            word[--wlen] = '\0';
        if (wlen == 0) continue;

        attempt++;
        make_key(word, key);

        /* Encrypt the known plaintext with this candidate key */
        unsigned char ct[256];
        int ct_len = aes_cbc_encrypt(key, IV, PLAINTEXT, PT_LEN, ct, sizeof(ct));

        if (ct_len == CT_LEN && memcmp(ct, EXPECTED_CT, CT_LEN) == 0) {
            end = clock();
            elapsed = (double)(end - start) / CLOCKS_PER_SEC;

            printf("\n  *** KEY FOUND! ***\n");
            printf("  Word:      %s\n", word);
            printf("  Key (hex): ");
            for (int i = 0; i < KEY_LEN; i++) printf("%02x", key[i]);
            printf("\n  Key (ascii): %s\n", key);
            printf("  Attempt:   %d\n", attempt);
            printf("  Time:      %.2f seconds\n", elapsed);

            /* Verify by decrypting */
            dec_len = aes_cbc_decrypt(key, IV, ct, ct_len, decrypted, sizeof(decrypted));
            if (dec_len > 0) {
                decrypted[dec_len] = '\0';
                printf("\n  Verification (decrypt): %s\n", decrypted);
                printf("  Match plaintext: %s\n",
                       memcmp(decrypted, PLAINTEXT, PT_LEN) == 0 ? "YES" : "NO");
            }

            found = 1;
            break;
        }

        if (attempt % 5000 == 0) {
            end = clock();
            elapsed = (double)(end - start) / CLOCKS_PER_SEC;
            printf("  ... checked %d words (%.1fs)\n", attempt, elapsed);
        }
    }

    fclose(fp);

    if (!found) {
        end = clock();
        elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        printf("\n  Key not found after %d attempts (%.1fs)\n", attempt, elapsed);
    }

    printf("\n============================================================\n");
    return found ? 0 : 1;
}

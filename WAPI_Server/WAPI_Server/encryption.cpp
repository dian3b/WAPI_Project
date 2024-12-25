#include <openssl/evp.h>
#include <openssl/err.h>

void encryptSM4(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, unsigned char** ciphertext, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptUpdate(ctx, NULL, &len, NULL, 0) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    *ciphertext = (unsigned char*)malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return;
    }
    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext);
        return;
    }
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void decryptSM4(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, unsigned char** plaintext, int* plaintext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, NULL, 0) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    *plaintext = (unsigned char*)malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return;
    }
    *plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return;
    }
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}
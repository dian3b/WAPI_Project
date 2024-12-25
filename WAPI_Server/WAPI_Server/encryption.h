#pragma once
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>

// º¯ÊıÉùÃ÷
void encryptSM4(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, unsigned char** ciphertext, int* ciphertext_len);
void decryptSM4(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, unsigned char** plaintext, int* plaintext_len);

#endif
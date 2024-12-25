#pragma once
#ifndef KEYEXCHANGE_H
#define KEYEXCHANGE_H

#include <openssl/dh.h>
#include <openssl/pem.h>

// º¯ÊýÉùÃ÷
void generateDHParams(DH** dh, BIGNUM** p, BIGNUM** g);
void calculateSharedSecret(const DH* dh, const BIGNUM* peerPublicKey, const BIGNUM* privateKey, unsigned char** sharedSecret, int* sharedSecretLen);

#endif
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void generateDHParams(DH** dh, BIGNUM** p, BIGNUM** g) {
    *dh = DH_new();
    if (!*dh) {
        ERR_print_errors_fp(stderr);
        return;
    }

    // 生成DH参数
    if (DH_generate_parameters_ex(*dh, 2048, 2, NULL) != 0) {
        *p = BN_dup(DH_get0_p(*dh));
        *g = BN_dup(DH_get0_g(*dh));
    }
    else {
        ERR_print_errors_fp(stderr);
        DH_free(*dh);
        *dh = NULL;
    }
}

void calculateSharedSecret(const DH* dh, const BIGNUM* peerPublicKey, const BIGNUM* privateKey, unsigned char** sharedSecret, int* sharedSecretLen) {
    *sharedSecret = (unsigned char*)malloc(DH_size(dh));
    *sharedSecretLen = DH_compute_key(*sharedSecret, peerPublicKey, dh, privateKey);
    if (*sharedSecretLen == -1) {
        ERR_print_errors_fp(stderr);
        free(*sharedSecret);
        *sharedSecret = NULL;
    }
}
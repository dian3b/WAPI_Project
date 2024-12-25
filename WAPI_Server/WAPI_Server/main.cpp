#include <iostream>
#include <openssl/err.h>
#include "certificate.h"
#include "encryption.h"
#include "keyexchange.h"

int main() {
    // 初始化OpenSSL库
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 数字证书验证示例
    const char* certFilePath = "path/to/certificate.pem";
    if (verifyCertificate(certFilePath)) {
        std::cout << "Certificate verified successfully." << std::endl;
    }
    else {
        std::cerr << "Certificate verification failed." << std::endl;
    }

    // 加密和解密示例
    const unsigned char* plaintext = (const unsigned char*)"This is a test message";
    int plaintext_len = strlen((const char*)plaintext);
    unsigned char* key = new unsigned char[16]; // 假设密钥长度为16字节
    generateKey(key, 16);
    unsigned char* ciphertext;
    int ciphertext_len;
    encryptSM4(plaintext, plaintext_len, key, &ciphertext, &ciphertext_len);
    std::cout << "Message encrypted." << std::endl;

    unsigned char* decrypted_text;
    int decrypted_text_len;
    decryptSM4(ciphertext, ciphertext_len, key, &decrypted_text, &decrypted_text_len);
    std::cout << "Decrypted message: " << (char*)decrypted_text << std::endl;

    // 密钥协商示例
    DH* dh;
    BIGNUM* p, * g;
    generateDHParams(&dh, &p, &g);
    BIGNUM* private_key = BN_new();
    BN_rand_range(private_key, dh->p);
    unsigned char* shared_secret;
    int shared_secret_len;
    calculateSharedSecret(dh, dh->pub_key, private_key, &shared_secret, &shared_secret_len);
    std::cout << "Shared secret generated." << std::endl;

    // 清理资源
    delete[] key;
    delete[] ciphertext;
    delete[] decrypted_text;
    BN_free(p);
    BN_free(g);
    BN_free(private_key);
    DH_free(dh);
    free(shared_secret);

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
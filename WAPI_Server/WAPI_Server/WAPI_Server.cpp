#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

bool verifyCertificate(const char* certFilePath) {
    FILE* certFile = fopen(certFilePath, "rb");
    if (!certFile) {
        perror("Failed to open certificate file");
        return false;
    }

    X509* cert = PEM_read_X509(certFile, NULL, 0, NULL);
    fclose(certFile);
    if (!cert) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 假设已有可信CA证书用于验证
    X509_STORE* store = X509_STORE_new();
    // 加载CA证书到存储中
    //...

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);

    int result = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);

    if (result == 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}
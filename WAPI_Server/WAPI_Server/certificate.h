#pragma once
#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <openssl/x509.h>

// ��������
bool verifyCertificate(const char* certFilePath);

#endif
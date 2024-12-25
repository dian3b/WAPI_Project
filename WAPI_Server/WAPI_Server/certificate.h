#pragma once
#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <openssl/x509.h>

// º¯ÊýÉùÃ÷
bool verifyCertificate(const char* certFilePath);

#endif
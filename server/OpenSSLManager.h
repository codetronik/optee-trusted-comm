#pragma once
#include <string>
#include <openssl/evp.h>
#include <openssl/x509.h>

class OpenSSLManager {
public:
    OpenSSLManager();
    ~OpenSSLManager();

    bool generateAndSave();
    bool loadFromFile();
    std::string getCertificatePem() const;
    std::string signCSR(const std::string& csrPem);

private:
    EVP_PKEY* _pkey;
    X509* _cert;

    bool saveToFile() const;
    std::string readFile(const std::string& path) const;
};

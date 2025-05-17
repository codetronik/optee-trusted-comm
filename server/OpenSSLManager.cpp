#include "OpenSSLManager.h"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <fstream>
#include <sstream>
#include <iostream>

OpenSSLManager::OpenSSLManager() : _pkey(nullptr), _cert(nullptr) {
    OpenSSL_add_all_algorithms();
}

OpenSSLManager::~OpenSSLManager() {
    if (_cert) X509_free(_cert);
    if (_pkey) EVP_PKEY_free(_pkey);
}

bool OpenSSLManager::generateAndSave() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) return false;

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    if (EVP_PKEY_keygen(pctx, &_pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    EVP_PKEY_CTX_free(pctx);

    _cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(_cert), 31536000L);
    X509_set_pubkey(_cert, _pkey);

    X509_NAME* name = X509_get_subject_name(_cert);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (const unsigned char*)"KR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (const unsigned char*)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"MyECCServer", -1, -1, 0);

    X509_set_issuer_name(_cert, name);
    if (!X509_sign(_cert, _pkey, EVP_sha256())) return false;

    return saveToFile();
}

bool OpenSSLManager::saveToFile() const {
    std::ofstream keyOut("server_key.pem");
    std::ofstream certOut("server_cert.pem");
    if (!keyOut.is_open() || !certOut.is_open()) return false;

    BIO* keyBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(keyBio, _pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* keyData;
    long keyLen = BIO_get_mem_data(keyBio, &keyData);
    keyOut.write(keyData, keyLen);
    BIO_free(keyBio);

    BIO* certBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, _cert);
    char* certData;
    long certLen = BIO_get_mem_data(certBio, &certData);
    certOut.write(certData, certLen);
    BIO_free(certBio);

    return true;
}

bool OpenSSLManager::loadFromFile() {
    if (_pkey) {
        EVP_PKEY_free(_pkey);
        _pkey = nullptr;
    }
    if (_cert) {
        X509_free(_cert);
        _cert = nullptr;
    }

    std::ifstream keyIn("server_key.pem", std::ios::binary);
    std::ifstream certIn("server_cert.pem", std::ios::binary);
    if (!keyIn.is_open()) {
        std::cerr << "[Error] Failed to open server_key.pem" << std::endl;
        return false;
    }
    if (!certIn.is_open()) {
        std::cerr << "[Error] Failed to open server_cert.pem" << std::endl;
        return false;
    }

    std::stringstream keyBuffer, certBuffer;
    keyBuffer << keyIn.rdbuf();
    certBuffer << certIn.rdbuf();

    std::string keyStr = keyBuffer.str();
    std::string certStr = certBuffer.str();

    if (keyStr.empty()) {
        std::cerr << "[Error] server_key.pem is empty" << std::endl;
        return false;
    }
    if (certStr.empty()) {
        std::cerr << "[Error] server_cert.pem is empty" << std::endl;
        return false;
    }

    BIO* keyBio = BIO_new_mem_buf(keyStr.data(), static_cast<int>(keyStr.size()));
    BIO* certBio = BIO_new_mem_buf(certStr.data(), static_cast<int>(certStr.size()));

    if (!keyBio || !certBio) {
        std::cerr << "[Error] Failed to create BIO buffers" << std::endl;
        if (keyBio) BIO_free(keyBio);
        if (certBio) BIO_free(certBio);
        return false;
    }

    _pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    _cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);

    BIO_free(keyBio);
    BIO_free(certBio);

    if (!_pkey) {
        std::cerr << "[Error] Failed to parse private key from server_key.pem" << std::endl;
        return false;
    }
    if (!_cert) {
        std::cerr << "[Error] Failed to parse certificate from server_cert.pem" << std::endl;
        EVP_PKEY_free(_pkey);
        _pkey = nullptr;
        return false;
    }

    std::cout << "[Info] Loaded certificate and key successfully." << std::endl;
    return true;
}

std::string OpenSSLManager::getCertificatePem() const {
    BIO* mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem, _cert);
    char* data;
    long len = BIO_get_mem_data(mem, &data);
    std::string result(data, len);
    BIO_free(mem);
    return result;
}

std::string OpenSSLManager::signCSR(const std::string& csrPem) {
    BIO* bio = BIO_new_mem_buf(csrPem.data(), static_cast<int>(csrPem.size()));
    if (!bio) return "Failed to create BIO";

    X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!req) return "Invalid CSR";

    // 새 인증서 생성
    X509* newCert = X509_new();
    if (!newCert) {
        X509_REQ_free(req);
        return "Failed to create new X509 certificate";
    }

    // 시리얼 번호 랜덤 생성 (64비트)
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (!serial) {
        X509_free(newCert);
        X509_REQ_free(req);
        return "Failed to create ASN1_INTEGER for serial";
    }

    BIGNUM* bn = BN_new();
    if (!bn) {
        ASN1_INTEGER_free(serial);
        X509_free(newCert);
        X509_REQ_free(req);
        return "Failed to create BIGNUM for serial";
    }

    // OpenSSL 3.0 이상 권장 안전한 난수 생성 함수 사용
    if (!BN_priv_rand(bn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        BN_free(bn);
        ASN1_INTEGER_free(serial);
        X509_free(newCert);
        X509_REQ_free(req);
        return "Failed to generate random serial number";
    }

    if (!BN_to_ASN1_INTEGER(bn, serial)) {
        BN_free(bn);
        ASN1_INTEGER_free(serial);
        X509_free(newCert);
        X509_REQ_free(req);
        return "Failed to convert BIGNUM to ASN1_INTEGER";
    }

    BN_free(bn);

    // 인증서 시리얼 번호 설정
    X509_set_serialNumber(newCert, serial);
    ASN1_INTEGER_free(serial);

    // 인증서 유효기간 설정: 지금부터 1년 (31536000초)
    X509_gmtime_adj(X509_get_notBefore(newCert), 0);
    X509_gmtime_adj(X509_get_notAfter(newCert), 31536000L);

    // CSR에서 subject 이름 복사
    X509_set_subject_name(newCert, X509_REQ_get_subject_name(req));

    // CA 인증서의 issuer 이름 복사
    X509_set_issuer_name(newCert, X509_get_subject_name(_cert));

    // CSR의 공개키 복사
    EVP_PKEY* reqKey = X509_REQ_get_pubkey(req);
    if (!reqKey) {
        X509_free(newCert);
        X509_REQ_free(req);
        return "Failed to get public key from CSR";
    }
    X509_set_pubkey(newCert, reqKey);
    EVP_PKEY_free(reqKey);

    // CSR의 확장들 복사 (예: SubjectAltName 등)
    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    if (exts) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
            X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
            X509_add_ext(newCert, ext, -1);
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    // 인증서 서명 (CA 개인키 사용, SHA-256 해시)
    if (!X509_sign(newCert, _pkey, EVP_sha256())) {
        X509_free(newCert);
        X509_REQ_free(req);
        return "Failed to sign certificate";
    }

    // 인증서 PEM으로 변환
    BIO* out = BIO_new(BIO_s_mem());
    if (!out) {
        X509_free(newCert);
        X509_REQ_free(req);
        return "Failed to create BIO for output";
    }

    if (!PEM_write_bio_X509(out, newCert)) {
        BIO_free(out);
        X509_free(newCert);
        X509_REQ_free(req);
        return "Failed to write certificate to PEM";
    }

    char* data;
    long len = BIO_get_mem_data(out, &data);
    std::string result(data, len);

    BIO_free(out);
    X509_free(newCert);
    X509_REQ_free(req);

    return result;
}

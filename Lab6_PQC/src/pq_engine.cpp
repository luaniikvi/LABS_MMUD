#include "pq_engine.hpp"
#include "utils.hpp"
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <memory>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/bio.h>
#include <openssl/objects.h>

namespace lab6 {
namespace pq_engine {

// ============================================================================
// OpenSSL Error Helpers
// ============================================================================

static std::string get_openssl_error() {
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string error(buf, len);
    BIO_free(bio);
    while (!error.empty() && (error.back() == '\n' || error.back() == '\r'))
        error.pop_back();
    return error;
}

static void check_openssl(bool condition, const std::string& msg) {
    if (!condition) {
        utils::fail_closed(msg + ": " + get_openssl_error());
    }
}

// ============================================================================
// Algorithm Helpers
// ============================================================================

PQAlgo parse_algo(const std::string& algo_str) {
    if (algo_str == "mldsa-44") return PQAlgo::ML_DSA_44;
    if (algo_str == "mldsa-65") return PQAlgo::ML_DSA_65;
    if (algo_str == "mlkem-512") return PQAlgo::ML_KEM_512;
    utils::fail_closed("Unknown algorithm: " + algo_str + " (use mldsa-44, mldsa-65, mlkem-512)");
    return PQAlgo::ML_DSA_44;
}

HashAlgo parse_hash(const std::string& hash_str) {
    if (hash_str == "sha256") return HashAlgo::SHA256;
    if (hash_str == "sha384") return HashAlgo::SHA384;
    utils::fail_closed("Unknown hash algorithm: " + hash_str + " (use sha256, sha384)");
    return HashAlgo::SHA256;
}

std::string algo_name(PQAlgo algo) {
    switch (algo) {
        case PQAlgo::ML_DSA_44: return "mldsa-44";
        case PQAlgo::ML_DSA_65: return "mldsa-65";
        case PQAlgo::ML_KEM_512: return "mlkem-512";
    }
    return "unknown";
}

std::string hash_name(HashAlgo hash) {
    switch (hash) {
        case HashAlgo::SHA256: return "sha256";
        case HashAlgo::SHA384: return "sha384";
    }
    return "unknown";
}

bool is_ml_dsa(PQAlgo algo) {
    return algo == PQAlgo::ML_DSA_44 || algo == PQAlgo::ML_DSA_65;
}

bool is_ml_kem(PQAlgo algo) {
    return algo == PQAlgo::ML_KEM_512;
}

static int get_nid(PQAlgo algo) {
    switch (algo) {
        case PQAlgo::ML_DSA_44: return NID_ML_DSA_44;
        case PQAlgo::ML_DSA_65: return NID_ML_DSA_65;
        case PQAlgo::ML_KEM_512: return NID_ML_KEM_512;
    }
    return NID_ML_DSA_44;
}

// ============================================================================
// Key Generation
// ============================================================================

void generate_keypair(PQAlgo algo,
                      const std::string& pub_file,
                      const std::string& priv_file) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(get_nid(algo), nullptr);
    check_openssl(ctx != nullptr, "Failed to create keygen context for " + algo_name(algo));

    check_openssl(EVP_PKEY_keygen_init(ctx) > 0, "Failed to init keygen for " + algo_name(algo));
    EVP_PKEY* pkey = nullptr;
    check_openssl(EVP_PKEY_keygen(ctx, &pkey) > 0, "Failed to generate " + algo_name(algo) + " key");
    EVP_PKEY_CTX_free(ctx);

    // Save PEM keys
    {
        BIO* bio = BIO_new(BIO_s_mem());
        check_openssl(PEM_write_bio_PUBKEY(bio, pkey) > 0, "Failed to write public key PEM");
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        utils::write_text_file(pub_file, std::string(data, len));
        BIO_free(bio);
    }
    {
        BIO* bio = BIO_new(BIO_s_mem());
        check_openssl(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) > 0,
                      "Failed to write private key PEM");
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        utils::write_text_file(priv_file, std::string(data, len));
        BIO_free(bio);
    }

    std::cout << "[INFO] " << algo_name(algo) << " key pair generated successfully" << std::endl;
    std::cout << "[INFO] Public key: " << pub_file << std::endl;
    std::cout << "[INFO] Private key: " << priv_file << std::endl;

    // Save DER format automatically
    {
        std::string pub_der = pub_file;
        size_t dot = pub_der.find_last_of('.');
        if (dot != std::string::npos) pub_der = pub_der.substr(0, dot);
        pub_der += ".der";
        BIO* bio = BIO_new(BIO_s_mem());
        check_openssl(i2d_PUBKEY_bio(bio, pkey) > 0, "Failed to write public DER");
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        utils::write_file(pub_der, std::vector<uint8_t>(data, data + len));
        BIO_free(bio);
        std::cout << "[INFO] DER public key: " << pub_der << std::endl;
    }
    {
        std::string priv_der = priv_file;
        size_t dot = priv_der.find_last_of('.');
        if (dot != std::string::npos) priv_der = priv_der.substr(0, dot);
        priv_der += ".der";
        BIO* bio = BIO_new(BIO_s_mem());
        check_openssl(i2d_PKCS8PrivateKey_bio(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) > 0,
                      "Failed to write private DER");
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        utils::write_file(priv_der, std::vector<uint8_t>(data, data + len));
        BIO_free(bio);
        std::cout << "[INFO] DER private key: " << priv_der << std::endl;
    }

    EVP_PKEY_free(pkey);
}

// ============================================================================
// Key Loading
// ============================================================================

void* load_private_key(const std::string& file, PQAlgo algo) {
    (void)algo;
    BIO* bio = BIO_new_file(file.c_str(), "r");
    check_openssl(bio != nullptr, "Cannot open private key file: " + file);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    check_openssl(pkey != nullptr, "Failed to load private key from: " + file);
    return pkey;
}

void* load_public_key(const std::string& file, PQAlgo algo) {
    (void)algo;
    std::string content = utils::read_text_file(file);
    BIO* bio = BIO_new_mem_buf(content.data(), static_cast<int>(content.size()));
    check_openssl(bio != nullptr, "Cannot create BIO for public key: " + file);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    check_openssl(pkey != nullptr, "Failed to load public key from: " + file);
    return pkey;
}

void free_key(void* key) {
    if (key) EVP_PKEY_free(static_cast<EVP_PKEY*>(key));
}

void save_public_key_der(void* pub_key, PQAlgo algo, const std::string& file) {
    (void)algo;
    BIO* bio = BIO_new(BIO_s_mem());
    check_openssl(i2d_PUBKEY_bio(bio, static_cast<EVP_PKEY*>(pub_key)) > 0, "Failed to write public DER");
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    utils::write_file(file, std::vector<uint8_t>(data, data + len));
    BIO_free(bio);
}

void save_private_key_der(void* priv_key, PQAlgo algo, const std::string& file) {
    (void)algo;
    BIO* bio = BIO_new(BIO_s_mem());
    check_openssl(i2d_PKCS8PrivateKey_bio(bio, static_cast<EVP_PKEY*>(priv_key), nullptr, nullptr, 0, nullptr, nullptr) > 0,
                  "Failed to write private DER");
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    utils::write_file(file, std::vector<uint8_t>(data, data + len));
    BIO_free(bio);
}

// ============================================================================
// ML-DSA Sign
// ============================================================================

std::vector<uint8_t> sign(void* priv_key, PQAlgo /*algo*/, HashAlgo hash,
                          const std::vector<uint8_t>& message) {
    (void)hash; // ML-DSA uses SHAKE internally, hash param is for the API signature
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(priv_key);
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    check_openssl(md_ctx != nullptr, "Failed to create signing context");

    check_openssl(EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) > 0,
                  "Failed to init ML-DSA sign");

    size_t sig_len = 0;
    check_openssl(EVP_DigestSign(md_ctx, nullptr, &sig_len, message.data(), message.size()) > 0,
                  "Failed to get ML-DSA signature length");

    std::vector<uint8_t> signature(sig_len);
    check_openssl(EVP_DigestSign(md_ctx, signature.data(), &sig_len, message.data(), message.size()) > 0,
                  "Failed to sign with ML-DSA");
    signature.resize(sig_len);
    EVP_MD_CTX_free(md_ctx);
    return signature;
}

// ============================================================================
// ML-DSA Verify
// ============================================================================

bool verify(void* pub_key, PQAlgo algo, HashAlgo hash,
            const std::vector<uint8_t>& message,
            const std::vector<uint8_t>& signature) {
    (void)algo;
    (void)hash;
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(pub_key);
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    check_openssl(md_ctx != nullptr, "Failed to create verify context");

    check_openssl(EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey) > 0,
                  "Failed to init ML-DSA verify");

    int result = EVP_DigestVerify(md_ctx, signature.data(), signature.size(),
                                   message.data(), message.size());
    EVP_MD_CTX_free(md_ctx);

    if (result == 1) return true;
    return false;
}

// ============================================================================
// ML-KEM Encapsulate
// ============================================================================

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(
    void* pub_key, PQAlgo algo) {
    (void)algo;
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(pub_key);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    check_openssl(ctx != nullptr, "Failed to create encapsulate context");

    check_openssl(EVP_PKEY_encapsulate_init(ctx, nullptr) > 0,
                  "Failed to init encapsulate");

    size_t ct_len = 0, ss_len = 0;
    check_openssl(EVP_PKEY_encapsulate(ctx, nullptr, &ct_len, nullptr, &ss_len) > 0,
                  "Failed to get encapsulate lengths");

    std::vector<uint8_t> ct(ct_len), ss(ss_len);
    check_openssl(EVP_PKEY_encapsulate(ctx, ct.data(), &ct_len, ss.data(), &ss_len) > 0,
                  "Failed to encapsulate");
    ct.resize(ct_len);
    ss.resize(ss_len);

    EVP_PKEY_CTX_free(ctx);
    return {ct, ss};
}

// ============================================================================
// ML-KEM Decapsulate
// ============================================================================

std::vector<uint8_t> decapsulate(
    void* priv_key, PQAlgo algo, const std::vector<uint8_t>& ciphertext) {
    (void)algo;
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(priv_key);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    check_openssl(ctx != nullptr, "Failed to create decapsulate context");

    check_openssl(EVP_PKEY_decapsulate_init(ctx, nullptr) > 0,
                  "Failed to init decapsulate");

    size_t ss_len = 0;
    check_openssl(EVP_PKEY_decapsulate(ctx, nullptr, &ss_len, ciphertext.data(), ciphertext.size()) > 0,
                  "Failed to get decapsulate length");

    std::vector<uint8_t> ss(ss_len);
    check_openssl(EVP_PKEY_decapsulate(ctx, ss.data(), &ss_len, ciphertext.data(), ciphertext.size()) > 0,
                  "Failed to decapsulate");
    ss.resize(ss_len);

    EVP_PKEY_CTX_free(ctx);
    return ss;
}

// ============================================================================
// Utility
// ============================================================================

int get_key_size(void* key, PQAlgo algo) {
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key);
    (void)algo;
    return EVP_PKEY_get_bits(pkey);
}

bool is_pem_file(const std::string& file) {
    auto content = utils::read_text_file(file);
    return content.find("-----BEGIN") != std::string::npos;
}

SigFormat parse_sig_format(const std::string& fmt) {
    if (fmt == "der") return SigFormat::DER;
    if (fmt == "raw") return SigFormat::RAW;
    if (fmt == "base64") return SigFormat::BASE64;
    utils::fail_closed("Invalid signature format: " + fmt + " (use der, raw, base64)");
    return SigFormat::DER;
}

} // namespace pq_engine
} // namespace lab6

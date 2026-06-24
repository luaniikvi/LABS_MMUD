#include "sig_engine.hpp"
#include "utils.hpp"
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <memory>

// Suppress OpenSSL 3.0 deprecation warnings
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

namespace lab5 {
namespace sig_engine {

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
    // Clean newlines
    while (!error.empty() && (error.back() == '\n' || error.back() == '\r'))
        error.pop_back();
    return error;
}

static void check_openssl(bool condition, const std::string& msg) {
    if (!condition) {
        std::string ossl_err = get_openssl_error();
        utils::fail_closed(msg + ": " + ossl_err);
    }
}

// ============================================================================
// Algorithm Helpers
// ============================================================================

SigAlgo parse_algo(const std::string& algo_str) {
    if (algo_str == "ecdsa-p256") return SigAlgo::ECDSA_P256;
    if (algo_str == "ecdsa-p384") return SigAlgo::ECDSA_P384;
    if (algo_str == "rsa-pss-3072") return SigAlgo::RSA_PSS_3072;
    utils::fail_closed("Unknown algorithm: " + algo_str + " (use ecdsa-p256, ecdsa-p384, rsa-pss-3072)");
    return SigAlgo::ECDSA_P256;
}

HashAlgo parse_hash(const std::string& hash_str) {
    if (hash_str == "sha256") return HashAlgo::SHA256;
    if (hash_str == "sha384") return HashAlgo::SHA384;
    utils::fail_closed("Unknown hash algorithm: " + hash_str + " (use sha256, sha384)");
    return HashAlgo::SHA256;
}

std::string algo_name(SigAlgo algo) {
    switch (algo) {
        case SigAlgo::ECDSA_P256: return "ecdsa-p256";
        case SigAlgo::ECDSA_P384: return "ecdsa-p384";
        case SigAlgo::RSA_PSS_3072: return "rsa-pss-3072";
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

static const EVP_MD* get_evp_md(HashAlgo hash) {
    switch (hash) {
        case HashAlgo::SHA256: return EVP_sha256();
        case HashAlgo::SHA384: return EVP_sha384();
    }
    return EVP_sha256();
}

static int get_nid(SigAlgo algo) {
    switch (algo) {
        case SigAlgo::ECDSA_P256: return NID_X9_62_prime256v1;
        case SigAlgo::ECDSA_P384: return NID_secp384r1;
        default: return -1;
    }
}

static bool is_ecdsa(SigAlgo algo) {
    return algo == SigAlgo::ECDSA_P256 || algo == SigAlgo::ECDSA_P384;
}

static bool is_rsa_pss(SigAlgo algo) {
    return algo == SigAlgo::RSA_PSS_3072;
}

// ============================================================================
// Key Generation
// ============================================================================

void generate_keypair(SigAlgo algo,
                      const std::string& pub_file,
                      const std::string& priv_file) {
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;

    if (is_ecdsa(algo)) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        check_openssl(ctx != nullptr, "Failed to create EC keygen context");

        check_openssl(EVP_PKEY_keygen_init(ctx) > 0, "Failed to init EC keygen");
        check_openssl(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, get_nid(algo)) > 0,
                      "Failed to set EC curve");

        // Generate
        check_openssl(EVP_PKEY_keygen(ctx, &pkey) > 0, "Failed to generate EC key");

    } else if (is_rsa_pss(algo)) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        check_openssl(ctx != nullptr, "Failed to create RSA keygen context");

        check_openssl(EVP_PKEY_keygen_init(ctx) > 0, "Failed to init RSA keygen");
        check_openssl(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) > 0,
                      "Failed to set RSA key size");

        // 65537 is the default public exponent — no need to set explicitly
        check_openssl(EVP_PKEY_keygen(ctx, &pkey) > 0, "Failed to generate RSA key");
    }

    EVP_PKEY_CTX_free(ctx);

    // Save PEM keys
    {
        BIO* bio = BIO_new(BIO_s_mem());
        check_openssl(PEM_write_bio_PUBKEY(bio, pkey) > 0, "Failed to write public key PEM");
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem_str(data, len);
        BIO_free(bio);
        utils::write_text_file(pub_file, pem_str);
    }

    {
        BIO* bio = BIO_new(BIO_s_mem());
        check_openssl(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) > 0,
                      "Failed to write private key PEM");
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem_str(data, len);
        BIO_free(bio);
        utils::write_text_file(priv_file, pem_str);
    }

    std::cout << "[INFO] " << algo_name(algo) << " key pair generated successfully" << std::endl;
    std::cout << "[INFO] Public key: " << pub_file << std::endl;
    std::cout << "[INFO] Private key: " << priv_file << std::endl;

    // Save DER format auto
    {
        std::string pub_der = pub_file;
        size_t dot = pub_der.find_last_of('.');
        if (dot != std::string::npos) pub_der = pub_der.substr(0, dot);
        pub_der += ".der";
        
        BIO* bio = BIO_new(BIO_s_mem());
        check_openssl(i2d_PUBKEY_bio(bio, pkey) > 0, "Failed to write public DER");
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::vector<uint8_t> der(data, data + len);
        BIO_free(bio);
        utils::write_file(pub_der, der);
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
        std::vector<uint8_t> der(data, data + len);
        BIO_free(bio);
        utils::write_file(priv_der, der);
        std::cout << "[INFO] DER private key: " << priv_der << std::endl;
    }

    EVP_PKEY_free(pkey);
}

// ============================================================================
// Key Loading
// ============================================================================

void* load_private_key(const std::string& file, SigAlgo algo) {
    (void)algo;
    BIO* bio = BIO_new_file(file.c_str(), "r");
    check_openssl(bio != nullptr, "Cannot open private key file: " + file);

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    check_openssl(pkey != nullptr, "Failed to load private key from: " + file);

    return pkey;
}

void* load_public_key(const std::string& file, SigAlgo algo) {
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

// ============================================================================
// DER Key Save
// ============================================================================

void save_public_key_der(void* pub_key, SigAlgo algo, const std::string& file) {
    (void)algo;
    BIO* bio = BIO_new(BIO_s_mem());
    check_openssl(i2d_PUBKEY_bio(bio, static_cast<EVP_PKEY*>(pub_key)) > 0,
                  "Failed to write public DER");
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::vector<uint8_t> der(data, data + len);
    BIO_free(bio);
    utils::write_file(file, der);
}

void save_private_key_der(void* priv_key, SigAlgo algo, const std::string& file) {
    (void)algo;
    BIO* bio = BIO_new(BIO_s_mem());
    check_openssl(i2d_PKCS8PrivateKey_bio(bio, static_cast<EVP_PKEY*>(priv_key), nullptr, nullptr, 0, nullptr, nullptr) > 0,
                  "Failed to write private DER");
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::vector<uint8_t> der(data, data + len);
    BIO_free(bio);
    utils::write_file(file, der);
}

// ============================================================================
// Sign
// ============================================================================

std::vector<uint8_t> sign(void* priv_key, SigAlgo algo, HashAlgo hash,
                          const std::vector<uint8_t>& message) {
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(priv_key);
    const EVP_MD* md = get_evp_md(hash);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    check_openssl(md_ctx != nullptr, "Failed to create signing context");

    if (is_rsa_pss(algo)) {
        // RSA-PSS: set padding mode and salt length
        EVP_PKEY_CTX* pctx = nullptr;
        check_openssl(EVP_DigestSignInit(md_ctx, &pctx, md, nullptr, pkey) > 0,
                      "Failed to init RSA-PSS sign");
        check_openssl(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0,
                      "Failed to set PSS padding");
        check_openssl(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, EVP_MD_size(md)) > 0,
                      "Failed to set PSS salt length");
        // Set MGF1 algorithm
        check_openssl(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0,
                      "Failed to set MGF1 hash");
    } else {
        // ECDSA: deterministic signing (OpenSSL 3.x+ defaults to RFC 6979)
        check_openssl(EVP_DigestSignInit(md_ctx, nullptr, md, nullptr, pkey) > 0,
                      "Failed to init ECDSA sign");
    }

    // Determine signature size
    size_t sig_len = 0;
    check_openssl(EVP_DigestSign(md_ctx, nullptr, &sig_len, message.data(), message.size()) > 0,
                  "Failed to get signature length");

    std::vector<uint8_t> signature(sig_len);
    check_openssl(EVP_DigestSign(md_ctx, signature.data(), &sig_len, message.data(), message.size()) > 0,
                  "Failed to sign");

    signature.resize(sig_len);
    EVP_MD_CTX_free(md_ctx);

    return signature;
}

// ============================================================================
// Verify
// ============================================================================

bool verify(void* pub_key, SigAlgo algo, HashAlgo hash,
            const std::vector<uint8_t>& message,
            const std::vector<uint8_t>& signature) {
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(pub_key);
    const EVP_MD* md = get_evp_md(hash);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    check_openssl(md_ctx != nullptr, "Failed to create verify context");

    if (is_rsa_pss(algo)) {
        EVP_PKEY_CTX* pctx = nullptr;
        check_openssl(EVP_DigestVerifyInit(md_ctx, &pctx, md, nullptr, pkey) > 0,
                      "Failed to init RSA-PSS verify");
        check_openssl(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0,
                      "Failed to set PSS padding");
        check_openssl(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, EVP_MD_size(md)) > 0,
                      "Failed to set PSS salt length");
        check_openssl(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0,
                      "Failed to set MGF1 hash");
    } else {
        check_openssl(EVP_DigestVerifyInit(md_ctx, nullptr, md, nullptr, pkey) > 0,
                      "Failed to init ECDSA verify");
    }

    int result = EVP_DigestVerify(md_ctx, signature.data(), signature.size(),
                                   message.data(), message.size());
    EVP_MD_CTX_free(md_ctx);

    if (result == 1) return true;
    // result == 0 means invalid signature
    // result < 0 means error (e.g. wrong key type) - also return false
    return false;
}

// ============================================================================
// Utility
// ============================================================================

size_t get_signature_size(SigAlgo algo) {
    switch (algo) {
        case SigAlgo::ECDSA_P256: return 72;   // DER max
        case SigAlgo::ECDSA_P384: return 104;  // DER max
        case SigAlgo::RSA_PSS_3072: return 384; // 3072/8 = 384 bytes
    }
    return 0;
}

int get_key_size(void* key, SigAlgo algo) {
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key);
    (void)algo;
    return EVP_PKEY_get_bits(pkey);
}

bool is_pem_file(const std::string& file) {
    auto content = utils::read_text_file(file);
    return content.find("-----BEGIN") != std::string::npos;
}

} // namespace sig_engine
} // namespace lab5

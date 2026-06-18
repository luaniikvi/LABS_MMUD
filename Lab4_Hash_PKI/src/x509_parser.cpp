#include "x509_parser.hpp"
#include "utils.hpp"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <sstream>
#include <iomanip>
#include <cstring>
#include <memory>

namespace lab4 {
namespace x509 {

// Helper: get OpenSSL error string
static std::string get_openssl_error() {
    char buf[256];
    unsigned long err = ERR_get_error();
    if (err) {
        ERR_error_string_n(err, buf, sizeof(buf));
        return std::string(buf);
    }
    return "Unknown OpenSSL error";
}

// Helper: X509_NAME to string
static std::string name_to_string(const X509_NAME* name) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "(error)";
    X509_NAME_print_ex(bio, const_cast<X509_NAME*>(name), 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// Helper: ASN1_TIME to string
static std::string time_to_string(const ASN1_TIME* time) {
    if (!time) return "(unknown)";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "(error)";
    ASN1_TIME_print(bio, time);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// Helper: ASN1_INTEGER to hex string
static std::string serial_to_hex(const ASN1_INTEGER* serial) {
    if (!serial) return "(unknown)";
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    if (!bn) return "(error)";
    char* hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    BN_free(bn);
    // Add colons for readability
    std::string formatted;
    for (size_t i = 0; i < result.size(); i += 2) {
        if (i > 0) formatted += ":";
        formatted += result.substr(i, 2);
    }
    return formatted;
}

// ============================================================================
// Parse certificate
// ============================================================================

CertInfo parse_certificate(const std::string& pem_path) {
    FILE* fp = fopen(pem_path.c_str(), "r");
    if (!fp) {
        utils::fail_closed("Cannot open certificate file: " + pem_path);
    }

    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!cert) {
        utils::fail_closed("Failed to parse X.509 certificate: " + get_openssl_error());
    }

    CertInfo info;

    // Version
    info.version = static_cast<int>(X509_get_version(cert)) + 1;

    // Subject & Issuer
    info.subject = name_to_string(X509_get_subject_name(cert));
    info.issuer = name_to_string(X509_get_issuer_name(cert));

    // Serial number
    info.serial_number = serial_to_hex(X509_get_serialNumber(cert));

    // Validity
    info.not_before = time_to_string(X509_get0_notBefore(cert));
    info.not_after = time_to_string(X509_get0_notAfter(cert));

    // Signature algorithm
    int sig_nid = X509_get_signature_nid(cert);
    info.signature_algo = OBJ_nid2ln(sig_nid);

    // Public key info
    EVP_PKEY* pubkey = X509_get0_pubkey(cert);
    if (pubkey) {
        int key_type = EVP_PKEY_base_id(pubkey);
        switch (key_type) {
            case EVP_PKEY_RSA:
                info.public_key_algo = "RSA";
                info.public_key_params = std::to_string(EVP_PKEY_bits(pubkey)) + " bit";
                break;
            case EVP_PKEY_EC: {
                info.public_key_algo = "EC";
                // Get curve name
                char curve_name[64] = {0};
                size_t len = sizeof(curve_name);
                if (EVP_PKEY_get_utf8_string_param(pubkey, "group", curve_name, len, &len)) {
                    info.public_key_params = std::string(curve_name);
                } else {
                    info.public_key_params = std::to_string(EVP_PKEY_bits(pubkey)) + " bit";
                }
                break;
            }
            default:
                info.public_key_algo = "Unknown";
                info.public_key_params = std::to_string(EVP_PKEY_bits(pubkey)) + " bit";
        }
    }

    // Key Usage extension
    uint32_t ku = X509_get_key_usage(cert);
    if (ku != UINT32_MAX) {
        if (ku & X509v3_KU_DIGITAL_SIGNATURE) info.key_usage.push_back("Digital Signature");
        if (ku & X509v3_KU_NON_REPUDIATION) info.key_usage.push_back("Non Repudiation");
        if (ku & X509v3_KU_KEY_ENCIPHERMENT) info.key_usage.push_back("Key Encipherment");
        if (ku & X509v3_KU_DATA_ENCIPHERMENT) info.key_usage.push_back("Data Encipherment");
        if (ku & X509v3_KU_KEY_AGREEMENT) info.key_usage.push_back("Key Agreement");
        if (ku & X509v3_KU_KEY_CERT_SIGN) info.key_usage.push_back("Certificate Sign");
        if (ku & X509v3_KU_CRL_SIGN) info.key_usage.push_back("CRL Sign");
    }

    // Subject Alternative Names
    GENERAL_NAMES* sans = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (sans) {
        int count = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < count; i++) {
            GENERAL_NAME* gen = sk_GENERAL_NAME_value(sans, i);
            if (gen->type == GEN_DNS) {
                const char* dns = reinterpret_cast<const char*>(
                    ASN1_STRING_get0_data(gen->d.dNSName));
                if (dns) info.san_entries.push_back(std::string("DNS: ") + dns);
            } else if (gen->type == GEN_EMAIL) {
                const char* email = reinterpret_cast<const char*>(
                    ASN1_STRING_get0_data(gen->d.rfc822Name));
                if (email) info.san_entries.push_back(std::string("Email: ") + email);
            } else if (gen->type == GEN_URI) {
                const char* uri = reinterpret_cast<const char*>(
                    ASN1_STRING_get0_data(gen->d.uniformResourceIdentifier));
                if (uri) info.san_entries.push_back(std::string("URI: ") + uri);
            }
        }
        GENERAL_NAMES_free(sans);
    }

    // SHA-256 fingerprint
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_len = 0;
    if (X509_digest(cert, EVP_sha256(), md, &md_len)) {
        std::ostringstream oss;
        for (unsigned int i = 0; i < md_len; i++) {
            if (i > 0) oss << ":";
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(md[i]);
        }
        info.fingerprint_sha256 = oss.str();
    }

    X509_free(cert);
    return info;
}

// ============================================================================
// Verify certificate signature
// ============================================================================

bool verify_signature(const std::string& cert_path, const std::string& issuer_pub_path) {
    // Load certificate
    FILE* fp = fopen(cert_path.c_str(), "r");
    if (!fp) {
        utils::fail_closed("Cannot open certificate: " + cert_path);
    }
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!cert) {
        utils::fail_closed("Failed to parse certificate: " + get_openssl_error());
    }

    // Load issuer public key
    fp = fopen(issuer_pub_path.c_str(), "r");
    if (!fp) {
        X509_free(cert);
        utils::fail_closed("Cannot open issuer public key: " + issuer_pub_path);
    }
    EVP_PKEY* issuer_key = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!issuer_key) {
        X509_free(cert);
        utils::fail_closed("Failed to parse issuer public key: " + get_openssl_error());
    }

    int result = X509_verify(cert, issuer_key);

    EVP_PKEY_free(issuer_key);
    X509_free(cert);

    return (result == 1);
}

// ============================================================================
// Format certificate info for display
// ============================================================================

std::string format_cert_info(const CertInfo& info) {
    std::ostringstream oss;
    oss << "========================================\n";
    oss << "  X.509 Certificate Information\n";
    oss << "========================================\n";
    oss << "Version:          v" << info.version << "\n";
    oss << "Serial Number:    " << info.serial_number << "\n";
    oss << "Subject:          " << info.subject << "\n";
    oss << "Issuer:           " << info.issuer << "\n";
    oss << "----------------------------------------\n";
    oss << "Public Key:       " << info.public_key_algo << " (" << info.public_key_params << ")\n";
    oss << "Signature Algo:   " << info.signature_algo << "\n";
    oss << "----------------------------------------\n";
    oss << "Not Before:       " << info.not_before << "\n";
    oss << "Not After:        " << info.not_after << "\n";
    oss << "----------------------------------------\n";
    oss << "SHA-256 Fingerprint:\n  " << info.fingerprint_sha256 << "\n";

    if (!info.key_usage.empty()) {
        oss << "----------------------------------------\n";
        oss << "Key Usage:\n";
        for (const auto& ku : info.key_usage) {
            oss << "  - " << ku << "\n";
        }
    }

    if (!info.san_entries.empty()) {
        oss << "----------------------------------------\n";
        oss << "Subject Alternative Names:\n";
        for (const auto& san : info.san_entries) {
            oss << "  - " << san << "\n";
        }
    }

    oss << "========================================\n";
    return oss.str();
}

} // namespace x509
} // namespace lab4

#define _CRT_SECURE_NO_WARNINGS
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
#include <vector>

namespace lab4 {
namespace x509 {

// Read a file into a memory BIO to avoid OpenSSL's applink/uplink issues on Windows.
// Returns nullptr on failure. Caller must BIO_free the result.
static BIO* bio_from_file(const std::string& path) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) return nullptr;

    std::fseek(fp, 0, SEEK_END);
    long size = std::ftell(fp);
    std::rewind(fp);

    std::vector<char> buf(size);
    size_t nread = std::fread(buf.data(), 1, size, fp);
    std::fclose(fp);

    if (static_cast<long>(nread) != size) return nullptr;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return nullptr;
    BIO_write(bio, buf.data(), size);
    return bio;
}

static std::string get_openssl_error() {
    unsigned long err = ERR_get_error();
    if (!err) return "Unknown OpenSSL error";
    char buf[256] = {0};
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
}

static std::string name_to_string(const X509_NAME* name) {
    if (!name) return "(null)";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "(error)";
    X509_NAME_print_ex(bio, const_cast<X509_NAME*>(name), 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(len ? data : "", len ? (size_t)len : 0);
    BIO_free(bio);
    return result;
}

static std::string time_to_string(const ASN1_TIME* time) {
    if (!time) return "(unknown)";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "(error)";
    ASN1_TIME_print(bio, time);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(len ? data : "", len ? (size_t)len : 0);
    BIO_free(bio);
    return result;
}

static std::string serial_to_hex(const ASN1_INTEGER* serial) {
    if (!serial) return "(unknown)";
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    if (!bn) return "(error)";
    char* hex = BN_bn2hex(bn);
    std::string result(hex ? hex : "(error)");
    if (hex) OPENSSL_free(hex);
    BN_free(bn);

    std::string formatted;
    for (size_t i = 0; i + 1 < result.size(); i += 2) {
        if (i) formatted += ':';
        formatted += result.substr(i, 2);
    }
    return formatted;
}

CertInfo parse_certificate(const std::string& pem_path) {
    BIO* bio = bio_from_file(pem_path);
    if (!bio) {
        utils::fail_closed("Cannot open certificate file: " + pem_path);
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) {
        utils::fail_closed("Failed to parse X.509 certificate: " + get_openssl_error());
    }

    CertInfo info;

    info.version = static_cast<int>(X509_get_version(cert)) + 1;
    info.subject = name_to_string(X509_get_subject_name(cert));
    info.issuer = name_to_string(X509_get_issuer_name(cert));
    info.serial_number = serial_to_hex(X509_get_serialNumber(cert));
    info.not_before = time_to_string(X509_get0_notBefore(cert));
    info.not_after = time_to_string(X509_get0_notAfter(cert));

    int sig_nid = X509_get_signature_nid(cert);
    info.signature_algo = OBJ_nid2ln(sig_nid);

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
                char curve_name[64] = {0};
                size_t len = sizeof(curve_name);
                if (EVP_PKEY_get_utf8_string_param(pubkey, "group", curve_name, len, &len)) {
                    info.public_key_params = std::string(curve_name, len);
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

    {
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
    }

    {
        GENERAL_NAMES* sans = nullptr;
        const X509_EXTENSION* ext = X509_get_ext(cert, X509v3_get_ext_by_NID(nullptr, NID_subject_alt_name, -1));
        if (ext) {
            sans = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(ext));
        }
        if (!sans) {
            sans = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, 0, nullptr));
        }
        if (sans) {
            int count = sk_GENERAL_NAME_num(sans);
            for (int i = 0; i < count; ++i) {
                GENERAL_NAME* gen = sk_GENERAL_NAME_value(sans, i);
                if (!gen) continue;
                if (gen->type == GEN_DNS) {
                    const char* dns = reinterpret_cast<const char*>(ASN1_STRING_get0_data(gen->d.dNSName));
                    if (dns) info.san_entries.emplace_back("DNS: ") += dns;
                } else if (gen->type == GEN_EMAIL) {
                    const char* email = reinterpret_cast<const char*>(ASN1_STRING_get0_data(gen->d.rfc822Name));
                    if (email) info.san_entries.emplace_back("Email: ") += email;
                } else if (gen->type == GEN_URI) {
                    const char* uri = reinterpret_cast<const char*>(ASN1_STRING_get0_data(gen->d.uniformResourceIdentifier));
                    if (uri) info.san_entries.emplace_back("URI: ") += uri;
                }
            }
            GENERAL_NAMES_free(sans);
        }
    }

    {
        unsigned char md[SHA256_DIGEST_LENGTH] = {0};
        unsigned int md_len = 0;
        if (X509_digest(cert, EVP_sha256(), md, &md_len)) {
            std::ostringstream oss;
            for (unsigned int i = 0; i < md_len; ++i) {
                if (i) oss << ':';
                oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(md[i]);
            }
            info.fingerprint_sha256 = oss.str();
        }
    }

    X509_free(cert);
    return info;
}

bool verify_signature(const std::string& cert_path, const std::string& issuer_pub_path) {
    BIO* bio = bio_from_file(cert_path);
    if (!bio) {
        utils::fail_closed("Cannot open certificate: " + cert_path);
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) {
        utils::fail_closed("Failed to parse certificate: " + get_openssl_error());
    }

    // 1. Validate Algorithm Consistency: Compare outer signature algorithm with inner TBSCertificate signature algorithm
    const X509_ALGOR* tbs_sigalg = X509_get0_tbs_sigalg(cert);
    const X509_ALGOR* outer_sigalg = nullptr;
    X509_get0_signature(nullptr, &outer_sigalg, cert);
    if (tbs_sigalg && outer_sigalg) {
        int tbs_nid = OBJ_obj2nid(tbs_sigalg->algorithm);
        int outer_nid = OBJ_obj2nid(outer_sigalg->algorithm);
        if (tbs_nid != outer_nid || tbs_nid == NID_undef) {
            X509_free(cert);
            utils::fail_closed("Algorithm Inconsistency: TBS signature algorithm and outer signature algorithm do not match.");
        }
    } else {
        X509_free(cert);
        utils::fail_closed("Failed to retrieve signature algorithms for consistency check.");
    }

    // 2. Verify TBS Structure Integrity
    long version = X509_get_version(cert);
    if (version < 0 || version > 2) {
        X509_free(cert);
        utils::fail_closed("Invalid certificate version: TBS structure is malformed.");
    }
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (!not_before || !not_after) {
        X509_free(cert);
        utils::fail_closed("Missing validity period in certificate TBS structure.");
    }
    if (!X509_get_subject_name(cert) || !X509_get_issuer_name(cert)) {
        X509_free(cert);
        utils::fail_closed("Missing subject or issuer name in certificate TBS structure.");
    }
    EVP_PKEY* subject_pub = X509_get0_pubkey(cert);
    if (!subject_pub) {
        X509_free(cert);
        utils::fail_closed("Missing subject public key in certificate TBS structure.");
    }

    // 3. Signature verification
    if (issuer_pub_path.empty()) {
        // Issuer key is unavailable
        // Check if self-signed: X509_check_issued checks if the cert is issued by itself
        if (X509_check_issued(cert, cert) == X509_V_OK) {
            int rc = X509_verify(cert, subject_pub);
            X509_free(cert);
            if (rc != 1) {
                utils::fail_closed("Self-signed signature verification failed.");
            }
            return true;
        } else {
            // Not self-signed, and issuer key is unavailable
            X509_free(cert);
            utils::fail_closed("Fail-closed: Issuer public key is unavailable and certificate is not self-signed.");
        }
    }

    // Issuer key is provided
    BIO* ibio = bio_from_file(issuer_pub_path);
    if (!ibio) {
        X509_free(cert);
        utils::fail_closed("Cannot open issuer public key: " + issuer_pub_path);
    }
    EVP_PKEY* issuer_key = PEM_read_bio_PUBKEY(ibio, nullptr, nullptr, nullptr);
    BIO_free(ibio);
    if (!issuer_key) {
        X509_free(cert);
        utils::fail_closed("Failed to parse issuer public key: " + get_openssl_error());
    }

    int rc = X509_verify(cert, issuer_key);
    EVP_PKEY_free(issuer_key);
    X509_free(cert);
    return rc == 1;
}

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
        for (const auto& ku : info.key_usage) oss << "  - " << ku << "\n";
    }

    if (!info.san_entries.empty()) {
        oss << "----------------------------------------\n";
        oss << "Subject Alternative Names:\n";
        for (const auto& san : info.san_entries) oss << "  - " << san << "\n";
    }

    oss << "========================================\n";
    return oss.str();
}

} // namespace x509
} // namespace lab4

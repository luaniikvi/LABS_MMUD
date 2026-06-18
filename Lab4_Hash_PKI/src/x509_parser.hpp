#pragma once

#include <string>
#include <vector>

namespace lab4 {
namespace x509 {

struct CertInfo {
    std::string subject;
    std::string issuer;
    std::string public_key_algo;    // "RSA", "EC", etc.
    std::string public_key_params;  // "2048 bit" or "secp256r1"
    std::string signature_algo;     // "sha256WithRSAEncryption"
    std::string not_before;
    std::string not_after;
    std::vector<std::string> key_usage;
    std::vector<std::string> san_entries;  // Subject Alternative Names
    std::string serial_number;
    std::string fingerprint_sha256;
    int version = 0;
};

// Parse X.509 certificate from PEM file
CertInfo parse_certificate(const std::string& pem_path);

// Verify certificate signature using issuer's public key
bool verify_signature(const std::string& cert_path, const std::string& issuer_pub_path);

// Format certificate info for display
std::string format_cert_info(const CertInfo& info);

} // namespace x509
} // namespace lab4

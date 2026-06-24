#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace lab5 {
namespace sig_engine {

// Algorithm identifiers
enum class SigAlgo {
    ECDSA_P256,
    ECDSA_P384,
    RSA_PSS_3072
};

// Hash algorithm identifiers
enum class HashAlgo {
    SHA256,
    SHA384
};

// Signature format
enum class SigFormat {
    DER,      // DER-encoded signature (default for ECDSA)
    RAW,      // Raw r||s (for ECDSA) or raw bytes (for RSA-PSS)
    BASE64    // Base64-encoded DER
};

// Parse algorithm string: "ecdsa-p256", "ecdsa-p384", "rsa-pss-3072"
SigAlgo parse_algo(const std::string& algo_str);

// Parse hash string: "sha256", "sha384"
HashAlgo parse_hash(const std::string& hash_str);

// Get algorithm name string
std::string algo_name(SigAlgo algo);
std::string hash_name(HashAlgo hash);

// Key generation
void generate_keypair(SigAlgo algo,
                      const std::string& pub_file,
                      const std::string& priv_file);

// Load keys (returns opaque pointer to EVP_PKEY — caller must manage)
// We use void* to avoid requiring OpenSSL headers in the header file.
// In practice, these return EVP_PKEY*.

void* load_private_key(const std::string& file, SigAlgo algo);
void* load_public_key(const std::string& file, SigAlgo algo);

// Free loaded key
void free_key(void* key);

// Save keys in DER format
void save_public_key_der(void* pub_key, SigAlgo algo, const std::string& file);
void save_private_key_der(void* priv_key, SigAlgo algo, const std::string& file);

// Sign a message. Returns DER-encoded signature.
std::vector<uint8_t> sign(void* priv_key, SigAlgo algo, HashAlgo hash,
                          const std::vector<uint8_t>& message);

// Verify a DER-encoded signature
bool verify(void* pub_key, SigAlgo algo, HashAlgo hash,
            const std::vector<uint8_t>& message,
            const std::vector<uint8_t>& signature);

// Get signature size estimate
size_t get_signature_size(SigAlgo algo);

// Get key size in bits
int get_key_size(void* key, SigAlgo algo);

// PEM format detection
bool is_pem_file(const std::string& file);

} // namespace sig_engine
} // namespace lab5

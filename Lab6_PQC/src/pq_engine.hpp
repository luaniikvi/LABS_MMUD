#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace lab6 {
namespace pq_engine {

// PQC algorithm identifiers
enum class PQAlgo {
    ML_DSA_44,
    ML_DSA_65,
    ML_KEM_512
};

// Hash algorithm identifiers
enum class HashAlgo {
    SHA256,
    SHA384
};

// Parse algorithm string: "mldsa-44", "mldsa-65", "mlkem-512"
PQAlgo parse_algo(const std::string& algo_str);

// Parse hash string: "sha256", "sha384"
HashAlgo parse_hash(const std::string& hash_str);

// Get algorithm name string
std::string algo_name(PQAlgo algo);
std::string hash_name(HashAlgo hash);

// Key generation
void generate_keypair(PQAlgo algo,
                      const std::string& pub_file,
                      const std::string& priv_file);

// Load keys (returns opaque pointer to EVP_PKEY)
void* load_private_key(const std::string& file, PQAlgo algo);
void* load_public_key(const std::string& file, PQAlgo algo);

// Free loaded key
void free_key(void* key);

// Save keys in DER format
void save_public_key_der(void* pub_key, PQAlgo algo, const std::string& file);
void save_private_key_der(void* priv_key, PQAlgo algo, const std::string& file);

// Sign a message (ML-DSA only). Returns DER-encoded signature.
std::vector<uint8_t> sign(void* priv_key, PQAlgo algo, HashAlgo hash,
                          const std::vector<uint8_t>& message);

// Verify a signature (ML-DSA only)
bool verify(void* pub_key, PQAlgo algo, HashAlgo hash,
            const std::vector<uint8_t>& message,
            const std::vector<uint8_t>& signature);

// KEM encapsulation (ML-KEM only)
// Returns (ciphertext, shared_secret)
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(
    void* pub_key, PQAlgo algo);

// KEM decapsulation (ML-KEM only)
std::vector<uint8_t> decapsulate(
    void* priv_key, PQAlgo algo, const std::vector<uint8_t>& ciphertext);

// Get key size in bits
int get_key_size(void* key, PQAlgo algo);

// PEM format detection
bool is_pem_file(const std::string& file);

// Algorithm type detection
bool is_ml_dsa(PQAlgo algo);
bool is_ml_kem(PQAlgo algo);

// Signature format
enum class SigFormat { DER, RAW, BASE64 };
SigFormat parse_sig_format(const std::string& fmt);

} // namespace pq_engine
} // namespace lab6

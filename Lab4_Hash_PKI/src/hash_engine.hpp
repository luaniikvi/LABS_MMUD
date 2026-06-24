#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lab4 {
namespace hash_engine {

// Supported algorithm identifiers
enum class Algorithm {
    SHA224, SHA256, SHA384, SHA512,
    SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHAKE128, SHAKE256,
    MD5
};

// Parse algorithm name string to enum
Algorithm parse_algorithm(const std::string& name);

// Get algorithm display name
std::string algorithm_name(Algorithm algo);

// Get digest size in bytes (0 for SHAKE — variable output)
size_t digest_size(Algorithm algo);

// Standard hash (fixed output)
std::vector<uint8_t> compute_hash(Algorithm algo, const uint8_t* data, size_t len);
std::vector<uint8_t> compute_hash(Algorithm algo, const std::vector<uint8_t>& data);

// Streaming hash (for large files, reads in 64KB chunks)
std::vector<uint8_t> compute_hash_stream(Algorithm algo, const std::string& filepath);

// SHAKE (variable output length)
std::vector<uint8_t> compute_shake(Algorithm algo, const uint8_t* data, size_t len, size_t output_bytes);
std::vector<uint8_t> compute_shake(Algorithm algo, const std::vector<uint8_t>& data, size_t output_bytes);
std::vector<uint8_t> compute_shake_stream(Algorithm algo, const std::string& filepath, size_t output_bytes);

// HMAC (SHA-256 or SHA-512)
std::vector<uint8_t> compute_hmac(Algorithm algo, const uint8_t* key, size_t key_len,
                                   const uint8_t* data, size_t data_len);
std::vector<uint8_t> compute_hmac(Algorithm algo, const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& data);
std::vector<uint8_t> compute_hmac_stream(Algorithm algo, const std::vector<uint8_t>& key,
                                          const std::string& filepath);

// Convenience: MD5
std::vector<uint8_t> compute_md5(const uint8_t* data, size_t len);
std::vector<uint8_t> compute_md5(const std::vector<uint8_t>& data);

} // namespace hash_engine
} // namespace lab4

#include "hash_engine.hpp"
#include "utils.hpp"

#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hmac.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <fstream>
#include <algorithm>
#include <memory>
#include <stdexcept>

namespace lab4 {
namespace hash_engine {

// ============================================================================
// Algorithm parsing
// ============================================================================

Algorithm parse_algorithm(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // Remove hyphens for flexible matching
    std::string clean;
    for (char c : lower) {
        if (c != '-' && c != '_') clean += c;
    }

    if (clean == "sha224" || clean == "sha2-224") return Algorithm::SHA224;
    if (clean == "sha256" || clean == "sha2-256") return Algorithm::SHA256;
    if (clean == "sha384" || clean == "sha2-384") return Algorithm::SHA384;
    if (clean == "sha512" || clean == "sha2-512") return Algorithm::SHA512;
    if (clean == "sha3224" || clean == "sha3-224") return Algorithm::SHA3_224;
    if (clean == "sha3256" || clean == "sha3-256") return Algorithm::SHA3_256;
    if (clean == "sha3384" || clean == "sha3-384") return Algorithm::SHA3_384;
    if (clean == "sha3512" || clean == "sha3-512") return Algorithm::SHA3_512;
    if (clean == "shake128") return Algorithm::SHAKE128;
    if (clean == "shake256") return Algorithm::SHAKE256;
    if (clean == "md5") return Algorithm::MD5;

    utils::fail_closed("Unsupported algorithm: " + name);
    return Algorithm::SHA256; // unreachable
}

std::string algorithm_name(Algorithm algo) {
    switch (algo) {
        case Algorithm::SHA224:    return "SHA-224";
        case Algorithm::SHA256:    return "SHA-256";
        case Algorithm::SHA384:    return "SHA-384";
        case Algorithm::SHA512:    return "SHA-512";
        case Algorithm::SHA3_224:  return "SHA3-224";
        case Algorithm::SHA3_256:  return "SHA3-256";
        case Algorithm::SHA3_384:  return "SHA3-384";
        case Algorithm::SHA3_512:  return "SHA3-512";
        case Algorithm::SHAKE128:  return "SHAKE128";
        case Algorithm::SHAKE256:  return "SHAKE256";
        case Algorithm::MD5:       return "MD5";
    }
    return "Unknown";
}

size_t digest_size(Algorithm algo) {
    switch (algo) {
        case Algorithm::SHA224:    return CryptoPP::SHA224::DIGESTSIZE;
        case Algorithm::SHA256:    return CryptoPP::SHA256::DIGESTSIZE;
        case Algorithm::SHA384:    return CryptoPP::SHA384::DIGESTSIZE;
        case Algorithm::SHA512:    return CryptoPP::SHA512::DIGESTSIZE;
        case Algorithm::SHA3_224:  return CryptoPP::SHA3_224::DIGESTSIZE;
        case Algorithm::SHA3_256:  return CryptoPP::SHA3_256::DIGESTSIZE;
        case Algorithm::SHA3_384:  return CryptoPP::SHA3_384::DIGESTSIZE;
        case Algorithm::SHA3_512:  return CryptoPP::SHA3_512::DIGESTSIZE;
        case Algorithm::SHAKE128:  return 0; // variable
        case Algorithm::SHAKE256:  return 0; // variable
        case Algorithm::MD5:       return CryptoPP::Weak1::MD5::DIGESTSIZE;
    }
    return 0;
}

// ============================================================================
// Helper: generic hash using CryptoPP::HashTransformation
// ============================================================================

static std::vector<uint8_t> hash_with(CryptoPP::HashTransformation& hash,
                                       const uint8_t* data, size_t len) {
    hash.Restart();
    hash.Update(data, len);
    std::vector<uint8_t> digest(hash.DigestSize());
    hash.Final(digest.data());
    return digest;
}

// ============================================================================
// Standard hash (in-memory)
// ============================================================================

std::vector<uint8_t> compute_hash(Algorithm algo, const uint8_t* data, size_t len) {
    switch (algo) {
        case Algorithm::SHA224: {
            CryptoPP::SHA224 h; return hash_with(h, data, len);
        }
        case Algorithm::SHA256: {
            CryptoPP::SHA256 h; return hash_with(h, data, len);
        }
        case Algorithm::SHA384: {
            CryptoPP::SHA384 h; return hash_with(h, data, len);
        }
        case Algorithm::SHA512: {
            CryptoPP::SHA512 h; return hash_with(h, data, len);
        }
        case Algorithm::SHA3_224: {
            CryptoPP::SHA3_224 h; return hash_with(h, data, len);
        }
        case Algorithm::SHA3_256: {
            CryptoPP::SHA3_256 h; return hash_with(h, data, len);
        }
        case Algorithm::SHA3_384: {
            CryptoPP::SHA3_384 h; return hash_with(h, data, len);
        }
        case Algorithm::SHA3_512: {
            CryptoPP::SHA3_512 h; return hash_with(h, data, len);
        }
        case Algorithm::MD5: {
            CryptoPP::Weak1::MD5 h; return hash_with(h, data, len);
        }
        case Algorithm::SHAKE128:
        case Algorithm::SHAKE256:
            utils::fail_closed("Use compute_shake() for SHAKE algorithms");
    }
    utils::fail_closed("Unknown algorithm");
    return {};
}

std::vector<uint8_t> compute_hash(Algorithm algo, const std::vector<uint8_t>& data) {
    return compute_hash(algo, data.data(), data.size());
}

// ============================================================================
// Streaming hash (64KB chunks for large files)
// ============================================================================

static constexpr size_t STREAM_CHUNK_SIZE = 65536; // 64 KiB

static std::vector<uint8_t> stream_hash_with(CryptoPP::HashTransformation& hash,
                                              const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        utils::fail_closed("Cannot open file: " + filepath);
    }
    hash.Restart();
    std::vector<char> buffer(STREAM_CHUNK_SIZE);
    while (file.read(buffer.data(), STREAM_CHUNK_SIZE) || file.gcount() > 0) {
        hash.Update(reinterpret_cast<const uint8_t*>(buffer.data()),
                     static_cast<size_t>(file.gcount()));
    }
    std::vector<uint8_t> digest(hash.DigestSize());
    hash.Final(digest.data());
    return digest;
}

std::vector<uint8_t> compute_hash_stream(Algorithm algo, const std::string& filepath) {
    switch (algo) {
        case Algorithm::SHA224: { CryptoPP::SHA224 h; return stream_hash_with(h, filepath); }
        case Algorithm::SHA256: { CryptoPP::SHA256 h; return stream_hash_with(h, filepath); }
        case Algorithm::SHA384: { CryptoPP::SHA384 h; return stream_hash_with(h, filepath); }
        case Algorithm::SHA512: { CryptoPP::SHA512 h; return stream_hash_with(h, filepath); }
        case Algorithm::SHA3_224: { CryptoPP::SHA3_224 h; return stream_hash_with(h, filepath); }
        case Algorithm::SHA3_256: { CryptoPP::SHA3_256 h; return stream_hash_with(h, filepath); }
        case Algorithm::SHA3_384: { CryptoPP::SHA3_384 h; return stream_hash_with(h, filepath); }
        case Algorithm::SHA3_512: { CryptoPP::SHA3_512 h; return stream_hash_with(h, filepath); }
        case Algorithm::MD5: { CryptoPP::Weak1::MD5 h; return stream_hash_with(h, filepath); }
        case Algorithm::SHAKE128:
        case Algorithm::SHAKE256:
            utils::fail_closed("Use compute_shake_stream() for SHAKE algorithms");
    }
    utils::fail_closed("Unknown algorithm");
    return {};
}

// ============================================================================
// SHAKE (variable output)
// ============================================================================

std::vector<uint8_t> compute_shake(Algorithm algo, const uint8_t* data, size_t len,
                                    size_t output_bytes) {
    if (output_bytes == 0) output_bytes = (algo == Algorithm::SHAKE128) ? 32 : 64;
    std::vector<uint8_t> digest(output_bytes);

    if (algo == Algorithm::SHAKE128) {
        CryptoPP::SHAKE128 shake;
        shake.Update(data, len);
        shake.TruncatedFinal(digest.data(), output_bytes);
    } else if (algo == Algorithm::SHAKE256) {
        CryptoPP::SHAKE256 shake;
        shake.Update(data, len);
        shake.TruncatedFinal(digest.data(), output_bytes);
    } else {
        utils::fail_closed("Not a SHAKE algorithm: " + algorithm_name(algo));
    }
    return digest;
}

std::vector<uint8_t> compute_shake(Algorithm algo, const std::vector<uint8_t>& data,
                                    size_t output_bytes) {
    return compute_shake(algo, data.data(), data.size(), output_bytes);
}

std::vector<uint8_t> compute_shake_stream(Algorithm algo, const std::string& filepath,
                                           size_t output_bytes) {
    if (output_bytes == 0) output_bytes = (algo == Algorithm::SHAKE128) ? 32 : 64;

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        utils::fail_closed("Cannot open file: " + filepath);
    }

    std::vector<uint8_t> digest(output_bytes);
    std::vector<char> buffer(STREAM_CHUNK_SIZE);

    if (algo == Algorithm::SHAKE128) {
        CryptoPP::SHAKE128 shake;
        while (file.read(buffer.data(), STREAM_CHUNK_SIZE) || file.gcount() > 0) {
            shake.Update(reinterpret_cast<const uint8_t*>(buffer.data()),
                         static_cast<size_t>(file.gcount()));
        }
        shake.TruncatedFinal(digest.data(), output_bytes);
    } else if (algo == Algorithm::SHAKE256) {
        CryptoPP::SHAKE256 shake;
        while (file.read(buffer.data(), STREAM_CHUNK_SIZE) || file.gcount() > 0) {
            shake.Update(reinterpret_cast<const uint8_t*>(buffer.data()),
                         static_cast<size_t>(file.gcount()));
        }
        shake.TruncatedFinal(digest.data(), output_bytes);
    } else {
        utils::fail_closed("Not a SHAKE algorithm: " + algorithm_name(algo));
    }
    return digest;
}

// ============================================================================
// HMAC
// ============================================================================

std::vector<uint8_t> compute_hmac(Algorithm algo, const uint8_t* key, size_t key_len,
                                   const uint8_t* data, size_t data_len) {
    std::vector<uint8_t> mac;

    switch (algo) {
        case Algorithm::SHA256: {
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key_len);
            hmac.Update(data, data_len);
            mac.resize(CryptoPP::SHA256::DIGESTSIZE);
            hmac.Final(mac.data());
            break;
        }
        case Algorithm::SHA512: {
            CryptoPP::HMAC<CryptoPP::SHA512> hmac(key, key_len);
            hmac.Update(data, data_len);
            mac.resize(CryptoPP::SHA512::DIGESTSIZE);
            hmac.Final(mac.data());
            break;
        }
        case Algorithm::SHA224: {
            CryptoPP::HMAC<CryptoPP::SHA224> hmac(key, key_len);
            hmac.Update(data, data_len);
            mac.resize(CryptoPP::SHA224::DIGESTSIZE);
            hmac.Final(mac.data());
            break;
        }
        case Algorithm::SHA384: {
            CryptoPP::HMAC<CryptoPP::SHA384> hmac(key, key_len);
            hmac.Update(data, data_len);
            mac.resize(CryptoPP::SHA384::DIGESTSIZE);
            hmac.Final(mac.data());
            break;
        }
        default:
            utils::fail_closed("HMAC not supported for: " + algorithm_name(algo) +
                               " (use SHA-224/256/384/512)");
    }
    return mac;
}

std::vector<uint8_t> compute_hmac(Algorithm algo, const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& data) {
    return compute_hmac(algo, key.data(), key.size(), data.data(), data.size());
}

std::vector<uint8_t> compute_hmac_stream(Algorithm algo, const std::vector<uint8_t>& key,
                                          const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        utils::fail_closed("Cannot open file: " + filepath);
    }
    std::vector<char> buffer(STREAM_CHUNK_SIZE);

    switch (algo) {
        case Algorithm::SHA224: {
            CryptoPP::HMAC<CryptoPP::SHA224> hmac(key.data(), key.size());
            while (file.read(buffer.data(), STREAM_CHUNK_SIZE) || file.gcount() > 0) {
                hmac.Update(reinterpret_cast<const uint8_t*>(buffer.data()), static_cast<size_t>(file.gcount()));
            }
            std::vector<uint8_t> mac(CryptoPP::SHA224::DIGESTSIZE);
            hmac.Final(mac.data());
            return mac;
        }
        case Algorithm::SHA256: {
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(key.data(), key.size());
            while (file.read(buffer.data(), STREAM_CHUNK_SIZE) || file.gcount() > 0) {
                hmac.Update(reinterpret_cast<const uint8_t*>(buffer.data()), static_cast<size_t>(file.gcount()));
            }
            std::vector<uint8_t> mac(CryptoPP::SHA256::DIGESTSIZE);
            hmac.Final(mac.data());
            return mac;
        }
        case Algorithm::SHA384: {
            CryptoPP::HMAC<CryptoPP::SHA384> hmac(key.data(), key.size());
            while (file.read(buffer.data(), STREAM_CHUNK_SIZE) || file.gcount() > 0) {
                hmac.Update(reinterpret_cast<const uint8_t*>(buffer.data()), static_cast<size_t>(file.gcount()));
            }
            std::vector<uint8_t> mac(CryptoPP::SHA384::DIGESTSIZE);
            hmac.Final(mac.data());
            return mac;
        }
        case Algorithm::SHA512: {
            CryptoPP::HMAC<CryptoPP::SHA512> hmac(key.data(), key.size());
            while (file.read(buffer.data(), STREAM_CHUNK_SIZE) || file.gcount() > 0) {
                hmac.Update(reinterpret_cast<const uint8_t*>(buffer.data()), static_cast<size_t>(file.gcount()));
            }
            std::vector<uint8_t> mac(CryptoPP::SHA512::DIGESTSIZE);
            hmac.Final(mac.data());
            return mac;
        }
        default:
            utils::fail_closed("HMAC not supported for: " + algorithm_name(algo) +
                               " (use SHA-224/256/384/512)");
    }
    return {};
}

// ============================================================================
// MD5 convenience
// ============================================================================

std::vector<uint8_t> compute_md5(const uint8_t* data, size_t len) {
    return compute_hash(Algorithm::MD5, data, len);
}

std::vector<uint8_t> compute_md5(const std::vector<uint8_t>& data) {
    return compute_hash(Algorithm::MD5, data);
}

} // namespace hash_engine
} // namespace lab4

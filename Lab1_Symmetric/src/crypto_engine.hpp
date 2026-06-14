// crypto_engine.hpp
#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct CryptoConfig {
    std::string mode;

    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;

    std::string aad;

    std::string encodeMode = "hex";

    bool isAead = false;
    bool verbose = false;
    int threads = 1;
    bool allowEcb = false;
    bool noPadding = false;  // If true, use NO_PADDING for CBC/ECB (for NIST KAT testing)
    bool suppressWarnings = false;  // If true, suppress security warnings (for benchmarking)

    size_t tagLength = 16;
};

std::vector<uint8_t> EncryptAES(const std::vector<uint8_t>& plaintext, CryptoConfig& config, std::vector<uint8_t>& outTag);
std::vector<uint8_t> DecryptAES(const std::vector<uint8_t>& ciphertext, const CryptoConfig& config, const std::vector<uint8_t>& tag);

// Nonce reuse detection (CTR/GCM/CCM): documented in README.
void CheckKeyNonceReuse(const CryptoConfig& config);
void RegisterKeyNonceUse(const CryptoConfig& config);
void ClearNonceRegistry();  // For KAT testing: reset nonce reuse tracker

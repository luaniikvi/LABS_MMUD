#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lab4 {
namespace length_ext {

struct ExtensionResult {
    std::vector<uint8_t> forged_mac;      // SHA-256 of forged message
    std::vector<uint8_t> forged_message;   // original_padding || append_data
    std::string padding_hex;               // the MD-strengthening padding bytes
};

// Compute naive MAC: H(key || message) using SHA-256
std::vector<uint8_t> compute_mac(const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& message);

// Perform length-extension attack:
// Given: MAC = SHA-256(key || message), key_length, message_length
// Compute: forged MAC = SHA-256(key || message || padding || append_data)
// Without knowing the key!
ExtensionResult extend_mac(const std::vector<uint8_t>& original_mac,
                           size_t key_length,
                           size_t message_length,
                           const std::vector<uint8_t>& append_data);

// Verify: given key, original message, and forged extended message,
// check if forged_mac == SHA-256(key || forged_message)
bool verify_extension(const std::vector<uint8_t>& key,
                      const std::vector<uint8_t>& forged_message,
                      const std::vector<uint8_t>& forged_mac);

} // namespace length_ext
} // namespace lab4

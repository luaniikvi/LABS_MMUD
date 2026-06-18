#include "length_ext.hpp"
#include "utils.hpp"

#include <cryptopp/sha.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace lab4 {
namespace length_ext {

// ============================================================================
// Minimal SHA-256 implementation for length-extension attack
// We need direct access to internal state, which Crypto++ doesn't expose easily
// ============================================================================

namespace sha256_internal {

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static void compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++) {
        W[i] = (static_cast<uint32_t>(block[i*4]) << 24) |
               (static_cast<uint32_t>(block[i*4+1]) << 16) |
               (static_cast<uint32_t>(block[i*4+2]) << 8) |
               (static_cast<uint32_t>(block[i*4+3]));
    }
    for (int i = 16; i < 64; i++) {
        W[i] = gamma1(W[i-2]) + W[i-7] + gamma0(W[i-15]) + W[i-16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// Generate MD-strengthening padding for a message of total_bit_length bits
static std::vector<uint8_t> generate_padding(uint64_t total_byte_length) {
    std::vector<uint8_t> padding;
    padding.push_back(0x80); // padding start bit

    // Pad to 56 bytes mod 64
    uint64_t mod = total_byte_length % 64;
    size_t zeros_needed = (mod < 56) ? (56 - mod) : (64 + 56 - mod);
    for (size_t i = 0; i < zeros_needed; i++) {
        padding.push_back(0x00);
    }

    // Append 64-bit big-endian bit length
    uint64_t bit_length = total_byte_length * 8;
    for (int i = 7; i >= 0; i--) {
        padding.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
    }

    return padding;
}

// Extract SHA-256 state from a 32-byte digest (big-endian)
static void state_from_digest(uint32_t state[8], const uint8_t digest[32]) {
    for (int i = 0; i < 8; i++) {
        state[i] = (static_cast<uint32_t>(digest[i*4]) << 24) |
                   (static_cast<uint32_t>(digest[i*4+1]) << 16) |
                   (static_cast<uint32_t>(digest[i*4+2]) << 8) |
                   (static_cast<uint32_t>(digest[i*4+3]));
    }
}

// Serialize SHA-256 state to 32-byte digest (big-endian)
static void digest_from_state(uint8_t digest[32], const uint32_t state[8]) {
    for (int i = 0; i < 8; i++) {
        digest[i*4]   = static_cast<uint8_t>((state[i] >> 24) & 0xFF);
        digest[i*4+1] = static_cast<uint8_t>((state[i] >> 16) & 0xFF);
        digest[i*4+2] = static_cast<uint8_t>((state[i] >> 8) & 0xFF);
        digest[i*4+3] = static_cast<uint8_t>(state[i] & 0xFF);
    }
}

} // namespace sha256_internal

// ============================================================================
// Public API
// ============================================================================

std::vector<uint8_t> compute_mac(const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& message) {
    // Naive MAC: SHA-256(key || message)
    std::vector<uint8_t> data;
    data.reserve(key.size() + message.size());
    data.insert(data.end(), key.begin(), key.end());
    data.insert(data.end(), message.begin(), message.end());

    CryptoPP::SHA256 sha;
    sha.Update(data.data(), data.size());
    std::vector<uint8_t> mac(CryptoPP::SHA256::DIGESTSIZE);
    sha.Final(mac.data());
    return mac;
}

ExtensionResult extend_mac(const std::vector<uint8_t>& original_mac,
                           size_t key_length,
                           size_t message_length,
                           const std::vector<uint8_t>& append_data) {
    if (original_mac.size() != 32) {
        utils::fail_closed("Original MAC must be 32 bytes (SHA-256)");
    }

    ExtensionResult result;

    // Step 1: Calculate total byte length of (key || message)
    uint64_t total_length = static_cast<uint64_t>(key_length + message_length);

    // Step 2: Generate the MD-strengthening padding that was appended
    std::vector<uint8_t> padding = sha256_internal::generate_padding(total_length);

    // Step 3: Reconstruct SHA-256 internal state from the original MAC
    uint32_t state[8];
    sha256_internal::state_from_digest(state, original_mac.data());

    // Step 4: Compute total processed length (key + message + padding)
    uint64_t processed_length = total_length + padding.size();

    // Step 5: Build the forged message = original_message || padding || append_data
    // (We don't have the original message, so we return padding || append_data
    //  and let the caller reconstruct as: key || original_message || padding || append_data)
    result.forged_message = padding;
    result.forged_message.insert(result.forged_message.end(),
                                  append_data.begin(), append_data.end());

    // Store padding hex for display
    std::ostringstream oss;
    for (size_t i = 0; i < padding.size(); i++) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(padding[i]);
    }
    result.padding_hex = oss.str();

    // Step 6: Continue hashing with the append data
    // Process append_data in 64-byte blocks
    size_t remaining = append_data.size();
    size_t offset = 0;

    // If append_data doesn't fill a full block, we need to pad it too
    // First, process complete 64-byte blocks
    while (remaining >= 64) {
        sha256_internal::compress(state, append_data.data() + offset);
        offset += 64;
        remaining -= 64;
        processed_length += 64;
    }

    // Build final block(s) with MD padding for the extended data
    std::vector<uint8_t> final_data(append_data.begin() + offset, append_data.end());
    uint64_t final_total = processed_length + final_data.size();
    std::vector<uint8_t> final_padding = sha256_internal::generate_padding(final_total);
    final_data.insert(final_data.end(), final_padding.begin(), final_padding.end());

    // Process remaining blocks
    for (size_t i = 0; i < final_data.size(); i += 64) {
        uint8_t block[64];
        std::memcpy(block, final_data.data() + i, 64);
        sha256_internal::compress(state, block);
    }

    // Step 7: Extract forged MAC from final state
    result.forged_mac.resize(32);
    sha256_internal::digest_from_state(result.forged_mac.data(), state);

    return result;
}

bool verify_extension(const std::vector<uint8_t>& key,
                      const std::vector<uint8_t>& forged_message,
                      const std::vector<uint8_t>& forged_mac) {
    // Compute SHA-256(key || forged_message) and compare
    std::vector<uint8_t> data;
    data.reserve(key.size() + forged_message.size());
    data.insert(data.end(), key.begin(), key.end());
    data.insert(data.end(), forged_message.begin(), forged_message.end());

    CryptoPP::SHA256 sha;
    sha.Update(data.data(), data.size());
    std::vector<uint8_t> computed(CryptoPP::SHA256::DIGESTSIZE);
    sha.Final(computed.data());

    return (computed == forged_mac);
}

} // namespace length_ext
} // namespace lab4

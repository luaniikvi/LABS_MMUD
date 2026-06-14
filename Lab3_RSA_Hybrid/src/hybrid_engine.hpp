#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>

namespace lab3 {
namespace hybrid_engine {

// Hybrid envelope structure
struct Envelope {
    std::vector<uint8_t> wrapped_key;  // RSA-encrypted AES key
    std::vector<uint8_t> iv;           // AES-GCM IV (96-bit)
    std::vector<uint8_t> tag;          // AES-GCM authentication tag
    std::vector<uint8_t> ciphertext;   // AES-GCM encrypted data
    std::vector<uint8_t> aad;          // Additional authenticated data (optional)
    int rsa_modulus_bits;
    std::string hash_algo;
};

// Hybrid encryption: RSA-OAEP + AES-GCM
void encrypt_hybrid(const CryptoPP::RSA::PublicKey& pub_key,
                    const std::vector<uint8_t>& plaintext,
                    const std::string& out_file,
                    const std::string& label = "",
                    const std::vector<uint8_t>& aad = {});

// Hybrid decryption
void decrypt_hybrid(const CryptoPP::RSA::PrivateKey& priv_key,
                    const std::string& in_file,
                    const std::string& out_file,
                    const std::string& label = "");

// Save envelope to file (JSON header + binary payload)
void save_envelope(const Envelope& env, const std::string& file);

// Load envelope from file
Envelope load_envelope(const std::string& file);

// Generate random AES-256 key
std::vector<uint8_t> generate_aes_key();

// Generate random 96-bit IV
std::vector<uint8_t> generate_iv();

} // namespace hybrid_engine
} // namespace lab3

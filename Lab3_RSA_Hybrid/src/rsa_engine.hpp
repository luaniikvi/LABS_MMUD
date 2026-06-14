#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

namespace lab3 {
namespace rsa_engine {

// Key generation
void generate_keypair(int bits, 
                      const std::string& pub_file,
                      const std::string& priv_file,
                      const std::string& metadata_file);

// Load keys
CryptoPP::RSA::PublicKey load_public_key(const std::string& file);
CryptoPP::RSA::PrivateKey load_private_key(const std::string& file);

// Save keys in PEM format
void save_public_key_pem(const CryptoPP::RSA::PublicKey& key, const std::string& file);
void save_private_key_pem(const CryptoPP::RSA::PrivateKey& key, const std::string& file);

// Load keys from PEM format
CryptoPP::RSA::PublicKey load_public_key_pem(const std::string& file);
CryptoPP::RSA::PrivateKey load_private_key_pem(const std::string& file);

// RSA-OAEP encryption
std::vector<uint8_t> encrypt(const CryptoPP::RSA::PublicKey& pub_key,
                              const std::vector<uint8_t>& plaintext,
                              const std::string& label = "");

// RSA-OAEP decryption
std::vector<uint8_t> decrypt(const CryptoPP::RSA::PrivateKey& priv_key,
                              const std::vector<uint8_t>& ciphertext,
                              const std::string& label = "");

// Calculate max plaintext size for given key
size_t get_max_plaintext_size(int modulus_bits);

// Key size validation
void validate_key_size(int bits);

} // namespace rsa_engine
} // namespace lab3

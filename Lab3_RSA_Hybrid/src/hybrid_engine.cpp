#include "hybrid_engine.hpp"
#include "rsa_engine.hpp"
#include "utils.hpp"
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

namespace lab3 {
namespace hybrid_engine {

std::vector<uint8_t> generate_aes_key() {
    CryptoPP::AutoSeededRandomPool rng;
    std::vector<uint8_t> key(32); // AES-256
    rng.GenerateBlock(key.data(), key.size());
    return key;
}

std::vector<uint8_t> generate_iv() {
    CryptoPP::AutoSeededRandomPool rng;
    std::vector<uint8_t> iv(12); // 96-bit IV for GCM
    rng.GenerateBlock(iv.data(), iv.size());
    return iv;
}

void encrypt_hybrid(const CryptoPP::RSA::PublicKey& pub_key,
                    const std::vector<uint8_t>& plaintext,
                    const std::string& out_file,
                    const std::string& label,
                    const std::vector<uint8_t>& aad) {
    CryptoPP::AutoSeededRandomPool rng;

    // Step 1: Generate random AES-256 key
    std::vector<uint8_t> aes_key = generate_aes_key();
    std::cout << "[INFO] Generated AES-256 key" << std::endl;

    // Step 2: Encrypt AES key with RSA-OAEP
    std::vector<uint8_t> wrapped_key = rsa_engine::encrypt(pub_key, aes_key, label);
    std::cout << "[INFO] Wrapped AES key with RSA-OAEP-" << pub_key.GetModulus().BitCount() << std::endl;

    // Step 3: Generate random IV
    std::vector<uint8_t> iv = generate_iv();

    // Step 4: Encrypt plaintext with AES-GCM
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(16); // 128-bit tag

    CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
    encryption.SetKeyWithIV(aes_key.data(), static_cast<int>(aes_key.size()), iv.data(), static_cast<int>(iv.size()));

    // Use EncryptAndAuthenticate for correct AAD + plaintext + tag generation
    encryption.EncryptAndAuthenticate(
        ciphertext.data(),
        tag.data(), static_cast<int>(tag.size()),
        iv.data(), static_cast<int>(iv.size()),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        plaintext.data(), plaintext.size()
    );

    std::cout << "[INFO] Encrypted " << plaintext.size() << " bytes with AES-256-GCM" << std::endl;

    // Step 5: Create and save envelope
    Envelope env;
    env.wrapped_key = wrapped_key;
    env.iv = iv;
    env.tag = tag;
    env.ciphertext = ciphertext;
    env.aad = aad;
    env.rsa_modulus_bits = pub_key.GetModulus().BitCount();
    env.hash_algo = "SHA-256";

    save_envelope(env, out_file);
    std::cout << "[INFO] Envelope saved to: " << out_file << std::endl;
}

void decrypt_hybrid(const CryptoPP::RSA::PrivateKey& priv_key,
                    const std::string& in_file,
                    const std::string& out_file,
                    const std::string& label) {
    CryptoPP::AutoSeededRandomPool rng;

    // Step 1: Load envelope
    Envelope env = load_envelope(in_file);
    std::cout << "[INFO] Loaded envelope from: " << in_file << std::endl;

    // Step 2: Decrypt AES key with RSA-OAEP
    std::vector<uint8_t> aes_key = rsa_engine::decrypt(priv_key, env.wrapped_key, label);
    std::cout << "[INFO] Unwrapped AES key with RSA-OAEP" << std::endl;

    // Step 3: Decrypt ciphertext with AES-GCM
    std::vector<uint8_t> plaintext(env.ciphertext.size());
    std::vector<uint8_t> tag(16);
    std::copy(env.tag.begin(), env.tag.end(), tag.begin());

    CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
    decryption.SetKeyWithIV(aes_key.data(), aes_key.size(), env.iv.data(), env.iv.size());

    try {
        // Decrypt and verify using Crypto++ simplified API
        std::vector<uint8_t> decrypted(env.ciphertext.size());
        
        bool verified = decryption.DecryptAndVerify(
            decrypted.data(),
            tag.data(), static_cast<int>(tag.size()),
            env.iv.data(), static_cast<int>(env.iv.size()),
            env.aad.empty() ? nullptr : env.aad.data(),
            env.aad.size(),
            env.ciphertext.data(),
            env.ciphertext.size()
        );

        if (!verified) {
            utils::fail_closed("AES-GCM authentication failed: tampered ciphertext or wrong key");
        }

        // Copy verified plaintext
        plaintext = decrypted;

    } catch (const CryptoPP::Exception& e) {
        utils::fail_closed(std::string("AES-GCM decryption failed: ") + e.what());
    }

    // Step 4: Write plaintext to output
    utils::write_file(out_file, plaintext);
    std::cout << "[INFO] Decrypted " << plaintext.size() << " bytes" << std::endl;
    std::cout << "[INFO] Output saved to: " << out_file << std::endl;
}

void save_envelope(const Envelope& env, const std::string& file) {
    // Create JSON header
    json header = {
        {"mode", "RSA-OAEP-AES-GCM"},
        {"rsa_modulus", env.rsa_modulus_bits},
        {"hash", env.hash_algo},
        {"wrapped_key", utils::to_base64(env.wrapped_key)},
        {"iv", utils::to_base64(env.iv)},
        {"tag", utils::to_base64(env.tag)},
        {"aad", env.aad.empty() ? "" : utils::to_base64(env.aad)}
    };

    // Write JSON header
    std::string header_str = header.dump(2);
    std::vector<uint8_t> header_bytes(header_str.begin(), header_str.end());

    // Write to file: [4 bytes header size][header][ciphertext]
    std::ofstream out(file, std::ios::binary);
    if (!out.is_open()) {
        utils::fail_closed("Cannot write to file: " + file);
    }

    uint32_t header_size = static_cast<uint32_t>(header_bytes.size());
    out.write(reinterpret_cast<const char*>(&header_size), sizeof(header_size));
    out.write(reinterpret_cast<const char*>(header_bytes.data()), header_size);
    out.write(reinterpret_cast<const char*>(env.ciphertext.data()), env.ciphertext.size());
    out.close();
}

Envelope load_envelope(const std::string& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in.is_open()) {
        utils::fail_closed("Cannot open file: " + file);
    }

    // Read header size
    uint32_t header_size = 0;
    in.read(reinterpret_cast<char*>(&header_size), sizeof(header_size));

    // Read header
    std::string header_str(header_size, '\0');
    in.read(&header_str[0], header_size);

    // Parse JSON
    json header = json::parse(header_str);

    // Validate header
    if (header["mode"] != "RSA-OAEP-AES-GCM") {
        utils::fail_closed("Invalid envelope mode: expected RSA-OAEP-AES-GCM");
    }

    // Extract fields
    Envelope env;
    env.rsa_modulus_bits = header["rsa_modulus"];
    env.hash_algo = header["hash"];
    env.wrapped_key = utils::from_base64(header["wrapped_key"]);
    env.iv = utils::from_base64(header["iv"]);
    env.tag = utils::from_base64(header["tag"]);
    
    std::string aad_b64 = header["aad"];
    if (!aad_b64.empty()) {
        env.aad = utils::from_base64(aad_b64);
    }

    // Read ciphertext (rest of file)
    std::vector<uint8_t> ciphertext(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>()
    );
    env.ciphertext = ciphertext;

    in.close();
    return env;
}

} // namespace hybrid_engine
} // namespace lab3

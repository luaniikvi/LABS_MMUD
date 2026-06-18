#include "rsa_engine.hpp"
#include "utils.hpp"
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/oids.h>
#include <cryptopp/algparam.h>
#include <cryptopp/argnames.h>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace lab3 {
namespace rsa_engine {

void validate_key_size(int bits) {
    if (bits < 3072) {
        utils::fail_closed("RSA modulus must be >= 3072 bits (got " + std::to_string(bits) + ")");
    }
    if (bits != 3072 && bits != 4096) {
        utils::fail_closed("Unsupported RSA modulus size: " + std::to_string(bits) + " (use 3072 or 4096)");
    }
}

size_t get_max_plaintext_size(int modulus_bits) {
    // mLen <= k - 2*hLen - 2
    // k = modulus_bits / 8
    // hLen = 32 (SHA-256)
    size_t k = modulus_bits / 8;
    size_t hLen = 32; // SHA-256
    return k - 2 * hLen - 2;
}

void generate_keypair(int bits, 
                      const std::string& pub_file,
                      const std::string& priv_file,
                      const std::string& metadata_file) {
    validate_key_size(bits);

    CryptoPP::AutoSeededRandomPool rng;
    
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, bits);

    CryptoPP::RSA::PrivateKey private_key(params);
    CryptoPP::RSA::PublicKey public_key(params);

    // Save in PEM format
    save_public_key_pem(public_key, pub_file);
    save_private_key_pem(private_key, priv_file);

    // Save metadata
    json metadata = {
        {"creation_time", std::to_string(static_cast<long long>(std::time(nullptr)))},
        {"modulus_bits", bits},
        {"hash", "SHA-256"}
    };

    utils::write_text_file(metadata_file, metadata.dump(2));
    
    std::cout << "[INFO] RSA-" << bits << " key pair generated successfully" << std::endl;
    std::cout << "[INFO] Public key: " << pub_file << std::endl;
    std::cout << "[INFO] Private key: " << priv_file << std::endl;
    std::cout << "[INFO] Metadata: " << metadata_file << std::endl;
}

void save_public_key_pem(const CryptoPP::RSA::PublicKey& key, const std::string& file) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);
    
    // Save to file
    CryptoPP::FileSink fileSink(file.c_str());
    
    // Write PEM header
    std::string header = "-----BEGIN RSA PUBLIC KEY-----\n";
    fileSink.Put(reinterpret_cast<const CryptoPP::byte*>(header.data()), header.size());
    
    // Base64 encode the key
    CryptoPP::Base64Encoder encoder;
    encoder.Attach(new CryptoPP::Redirector(fileSink));
    
    // Transfer from queue to encoder
    queue.TransferTo(encoder);
    encoder.MessageEnd();
    
    // Write PEM footer
    std::string footer = "-----END RSA PUBLIC KEY-----\n";
    fileSink.Put(reinterpret_cast<const CryptoPP::byte*>(footer.data()), footer.size());
    fileSink.MessageEnd();
}

void save_private_key_pem(const CryptoPP::RSA::PrivateKey& key, const std::string& file) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);
    
    // Save to file
    CryptoPP::FileSink fileSink(file.c_str());
    
    // Write PEM header
    std::string header = "-----BEGIN RSA PRIVATE KEY-----\n";
    fileSink.Put(reinterpret_cast<const CryptoPP::byte*>(header.data()), header.size());
    
    // Base64 encode the key
    CryptoPP::Base64Encoder encoder;
    encoder.Attach(new CryptoPP::Redirector(fileSink));
    
    // Transfer from queue to encoder
    queue.TransferTo(encoder);
    encoder.MessageEnd();
    
    // Write PEM footer
    std::string footer = "-----END RSA PRIVATE KEY-----\n";
    fileSink.Put(reinterpret_cast<const CryptoPP::byte*>(footer.data()), footer.size());
    fileSink.MessageEnd();
}

CryptoPP::RSA::PublicKey load_public_key_pem(const std::string& file) {
    std::string pem = utils::read_text_file(file);
    
    // Find and extract base64 content
    size_t start = pem.find("-----BEGIN RSA PUBLIC KEY-----");
    size_t end = pem.find("-----END RSA PUBLIC KEY-----");
    
    if (start == std::string::npos || end == std::string::npos) {
        utils::fail_closed("Invalid PEM format in: " + file);
    }
    
    start = pem.find('\n', start) + 1;
    std::string b64 = pem.substr(start, end - start);
    
    // Remove whitespace
    b64.erase(std::remove_if(b64.begin(), b64.end(), ::isspace), b64.end());
    
    CryptoPP::ByteQueue queue;
    CryptoPP::StringSource(b64, true, new CryptoPP::Base64Decoder(
        new CryptoPP::Redirector(queue)
    ));
    
    CryptoPP::RSA::PublicKey key;
    key.Load(queue);
    
    return key;
}

CryptoPP::RSA::PrivateKey load_private_key_pem(const std::string& file) {
    std::string pem = utils::read_text_file(file);
    
    size_t start = pem.find("-----BEGIN RSA PRIVATE KEY-----");
    size_t end = pem.find("-----END RSA PRIVATE KEY-----");
    
    if (start == std::string::npos || end == std::string::npos) {
        utils::fail_closed("Invalid PEM format in: " + file);
    }
    
    start = pem.find('\n', start) + 1;
    std::string b64 = pem.substr(start, end - start);
    
    b64.erase(std::remove_if(b64.begin(), b64.end(), ::isspace), b64.end());
    
    CryptoPP::ByteQueue queue;
    CryptoPP::StringSource(b64, true, new CryptoPP::Base64Decoder(
        new CryptoPP::Redirector(queue)
    ));
    
    CryptoPP::RSA::PrivateKey key;
    key.Load(queue);
    
    return key;
}

CryptoPP::RSA::PublicKey load_public_key(const std::string& file) {
    return load_public_key_pem(file);
}

CryptoPP::RSA::PrivateKey load_private_key(const std::string& file) {
    return load_private_key_pem(file);
}

// ============================================================================
// DER Format (binary ASN.1)
// ============================================================================

void save_public_key_der(const CryptoPP::RSA::PublicKey& key, const std::string& file) {
    CryptoPP::FileSink sink(file.c_str(), true);
    key.DEREncode(sink);
}

void save_private_key_der(const CryptoPP::RSA::PrivateKey& key, const std::string& file) {
    CryptoPP::FileSink sink(file.c_str(), true);
    key.DEREncode(sink);
}

CryptoPP::RSA::PublicKey load_public_key_der(const std::string& file) {
    CryptoPP::FileSource source(file.c_str(), true);
    CryptoPP::RSA::PublicKey key;
    key.BERDecode(source);
    return key;
}

CryptoPP::RSA::PrivateKey load_private_key_der(const std::string& file) {
    CryptoPP::FileSource source(file.c_str(), true);
    CryptoPP::RSA::PrivateKey key;
    key.BERDecode(source);
    return key;
}

std::vector<uint8_t> encrypt(const CryptoPP::RSA::PublicKey& pub_key,
                              const std::vector<uint8_t>& plaintext,
                              const std::string& label) {
    CryptoPP::AutoSeededRandomPool rng;
    
    // Check plaintext size
    size_t max_size = get_max_plaintext_size(pub_key.GetModulus().BitCount());
    if (plaintext.size() > max_size) {
        utils::fail_closed("Plaintext too large for direct RSA encryption (" + 
                          std::to_string(plaintext.size()) + " > " + 
                          std::to_string(max_size) + " bytes). Use hybrid mode.");
    }
    
    CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor encryptor(pub_key);
    
    size_t ct_size = encryptor.CiphertextLength(plaintext.size());
    std::vector<uint8_t> ciphertext(ct_size);
    
    // Encrypt directly with OAEP label via NameValuePairs (avoids AssignFrom key corruption)
    if (!label.empty()) {
        CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(
            CryptoPP::Name::EncodingParameters(),
            CryptoPP::ConstByteArrayParameter(
                reinterpret_cast<const CryptoPP::byte*>(label.data()), label.size()));
        encryptor.Encrypt(rng, plaintext.data(), plaintext.size(), ciphertext.data(), params);
    } else {
        encryptor.Encrypt(rng, plaintext.data(), plaintext.size(), ciphertext.data());
    }
    
    return ciphertext;
}

std::vector<uint8_t> decrypt(const CryptoPP::RSA::PrivateKey& priv_key,
                              const std::vector<uint8_t>& ciphertext,
                              const std::string& label) {
    CryptoPP::AutoSeededRandomPool rng;
    
    CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Decryptor decryptor(priv_key);
    
    // Calculate expected ciphertext length from key size
    size_t expected_length = decryptor.FixedCiphertextLength();
    if (ciphertext.size() != expected_length) {
        utils::fail_closed("Invalid ciphertext length (expected " + 
                          std::to_string(expected_length) + 
                          ", got " + std::to_string(ciphertext.size()) + ")");
    }
    
    // Allocate buffer for plaintext
    size_t max_plaintext = decryptor.MaxPlaintextLength(ciphertext.size());
    
    // Decrypt using PK_DecryptorFilter with OAEP label
    CryptoPP::SecByteBlock recovered(max_plaintext);
    
    // Decrypt with OAEP label via NameValuePairs
    CryptoPP::DecodingResult result;
    if (!label.empty()) {
        CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(
            CryptoPP::Name::EncodingParameters(),
            CryptoPP::ConstByteArrayParameter(
                reinterpret_cast<const CryptoPP::byte*>(label.data()), label.size()));
        result = decryptor.Decrypt(rng, ciphertext.data(), ciphertext.size(), recovered.data(), params);
    } else {
        result = decryptor.Decrypt(rng, ciphertext.data(), ciphertext.size(), recovered.data());
    }
    
    if (!result.isValidCoding) {
        utils::fail_closed("RSA-OAEP decryption failed: invalid padding, wrong key, or wrong label");
    }
    
    // Resize to actual message length
    std::vector<uint8_t> plaintext(recovered.begin(), recovered.begin() + result.messageLength);
    return plaintext;
}

} // namespace rsa_engine
} // namespace lab3

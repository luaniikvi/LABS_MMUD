#include <catch2/catch_amalgamated.hpp>
#include "sig_engine.hpp"
#include "utils.hpp"
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>

using json = nlohmann::json;
using namespace lab5;

namespace fs = std::filesystem;

// ============================================================================
// Test Fixtures
// ============================================================================

struct ECDSAKeyFixture {
    std::string pub_file = "test_ecdsa_pub.pem";
    std::string priv_file = "test_ecdsa_priv.pem";
    sig_engine::SigAlgo algo = sig_engine::SigAlgo::ECDSA_P256;

    ECDSAKeyFixture() {
        sig_engine::generate_keypair(algo, pub_file, priv_file);
    }

    ~ECDSAKeyFixture() {
        try {
            fs::remove(pub_file);
            fs::remove(priv_file);
            // Remove DER files too
            std::string pub_der = pub_file;
            size_t d = pub_der.find_last_of('.');
            if (d != std::string::npos) pub_der = pub_der.substr(0, d) + ".der";
            std::string priv_der = priv_file;
            d = priv_der.find_last_of('.');
            if (d != std::string::npos) priv_der = priv_der.substr(0, d) + ".der";
            fs::remove(pub_der);
            fs::remove(priv_der);
        } catch (...) {}
    }
};

struct RSAPSSKeyFixture {
    std::string pub_file = "test_rsa_pub.pem";
    std::string priv_file = "test_rsa_priv.pem";
    sig_engine::SigAlgo algo = sig_engine::SigAlgo::RSA_PSS_3072;

    RSAPSSKeyFixture() {
        sig_engine::generate_keypair(algo, pub_file, priv_file);
    }

    ~RSAPSSKeyFixture() {
        try {
            fs::remove(pub_file);
            fs::remove(priv_file);
            std::string pub_der = pub_file;
            size_t d = pub_der.find_last_of('.');
            if (d != std::string::npos) pub_der = pub_der.substr(0, d) + ".der";
            std::string priv_der = priv_file;
            d = priv_der.find_last_of('.');
            if (d != std::string::npos) priv_der = priv_der.substr(0, d) + ".der";
            fs::remove(pub_der);
            fs::remove(priv_der);
        } catch (...) {}
    }
};

// ============================================================================
// Algorithm Parsing Tests
// ============================================================================

TEST_CASE("Algorithm Parsing", "[sig][parse]") {
    REQUIRE(sig_engine::parse_algo("ecdsa-p256") == sig_engine::SigAlgo::ECDSA_P256);
    REQUIRE(sig_engine::parse_algo("ecdsa-p384") == sig_engine::SigAlgo::ECDSA_P384);
    REQUIRE(sig_engine::parse_algo("rsa-pss-3072") == sig_engine::SigAlgo::RSA_PSS_3072);
    REQUIRE_THROWS(sig_engine::parse_algo("invalid-algo"));
}

TEST_CASE("Hash Parsing", "[sig][parse]") {
    REQUIRE(sig_engine::parse_hash("sha256") == sig_engine::HashAlgo::SHA256);
    REQUIRE(sig_engine::parse_hash("sha384") == sig_engine::HashAlgo::SHA384);
    REQUIRE_THROWS(sig_engine::parse_hash("sha1"));
}

// ============================================================================
// ECDSA P-256 Tests
// ============================================================================

TEST_CASE("ECDSA P-256 Key Generation", "[ecdsa][keygen]") {
    ECDSAKeyFixture fixture;
    REQUIRE(fs::exists(fixture.pub_file));
    REQUIRE(fs::exists(fixture.priv_file));

    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);
    REQUIRE(pub_key != nullptr);
    REQUIRE(sig_engine::get_key_size(pub_key, fixture.algo) == 256);
    sig_engine::free_key(pub_key);
}

TEST_CASE("ECDSA P-256 Sign/Verify - Small Message", "[ecdsa][sign]") {
    ECDSAKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);
    REQUIRE(priv_key != nullptr);
    REQUIRE(pub_key != nullptr);

    std::string message = "Hello, ECDSA!";
    auto msg_bytes = utils::string_to_bytes(message);

    auto signature = sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes);
    REQUIRE(!signature.empty());

    bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes, signature);
    REQUIRE(valid);

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

TEST_CASE("ECDSA P-256 - Modified Message Fails", "[ecdsa][negative]") {
    ECDSAKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::string message = "Original message";
    auto msg_bytes = utils::string_to_bytes(message);
    auto signature = sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes);

    // Modify message
    std::string tampered = "Tampered message";
    auto tampered_bytes = utils::string_to_bytes(tampered);
    bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, tampered_bytes, signature);
    REQUIRE_FALSE(valid);

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

TEST_CASE("ECDSA P-256 - Modified Signature Fails", "[ecdsa][negative]") {
    ECDSAKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::string message = "Test message";
    auto msg_bytes = utils::string_to_bytes(message);
    auto signature = sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes);

    // Modify signature
    if (!signature.empty()) {
        signature[signature.size() - 1] ^= 0xFF;
    }
    bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes, signature);
    REQUIRE_FALSE(valid);

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

TEST_CASE("ECDSA P-256 - Wrong Public Key Fails", "[ecdsa][negative]") {
    // Generate two separate keypairs with unique names to avoid file overwrites
    std::string pub1 = "test_wrong_pub1.pem", priv1 = "test_wrong_priv1.pem";
    std::string pub2 = "test_wrong_pub2.pem", priv2 = "test_wrong_priv2.pem";
    sig_engine::generate_keypair(sig_engine::SigAlgo::ECDSA_P256, pub1, priv1);
    sig_engine::generate_keypair(sig_engine::SigAlgo::ECDSA_P256, pub2, priv2);

    void* priv_key1 = sig_engine::load_private_key(priv1, sig_engine::SigAlgo::ECDSA_P256);
    void* pub_key2 = sig_engine::load_public_key(pub2, sig_engine::SigAlgo::ECDSA_P256);

    std::string message = "Test message";
    auto msg_bytes = utils::string_to_bytes(message);
    auto signature = sig_engine::sign(priv_key1, sig_engine::SigAlgo::ECDSA_P256, sig_engine::HashAlgo::SHA256, msg_bytes);

    bool valid = sig_engine::verify(pub_key2, sig_engine::SigAlgo::ECDSA_P256, sig_engine::HashAlgo::SHA256, msg_bytes, signature);
    REQUIRE_FALSE(valid);

    sig_engine::free_key(priv_key1);
    sig_engine::free_key(pub_key2);
    std::remove(pub1.c_str()); std::remove(priv1.c_str());
    std::remove(pub2.c_str()); std::remove(priv2.c_str());
    std::string pub1d = "test_wrong_pub1.der", priv1d = "test_wrong_priv1.der";
    std::string pub2d = "test_wrong_pub2.der", priv2d = "test_wrong_priv2.der";
    std::remove(pub1d.c_str()); std::remove(priv1d.c_str());
    std::remove(pub2d.c_str()); std::remove(priv2d.c_str());
}

TEST_CASE("ECDSA P-256 - Wrong Hash Fails", "[ecdsa][negative]") {
    ECDSAKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::string message = "Test message";
    auto msg_bytes = utils::string_to_bytes(message);
    auto signature = sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes);

    bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA384, msg_bytes, signature);
    REQUIRE_FALSE(valid);

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

// ============================================================================
// RSA-PSS Tests
// ============================================================================

TEST_CASE("RSA-PSS-3072 Key Generation", "[rsa-pss][keygen]") {
    RSAPSSKeyFixture fixture;
    REQUIRE(fs::exists(fixture.pub_file));
    REQUIRE(fs::exists(fixture.priv_file));

    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);
    REQUIRE(pub_key != nullptr);
    REQUIRE(sig_engine::get_key_size(pub_key, fixture.algo) >= 3072);
    sig_engine::free_key(pub_key);
}

TEST_CASE("RSA-PSS-3072 Sign/Verify - Small Message", "[rsa-pss][sign]") {
    RSAPSSKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::string message = "Hello, RSA-PSS!";
    auto msg_bytes = utils::string_to_bytes(message);

    auto signature = sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes);
    REQUIRE(!signature.empty());

    bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes, signature);
    REQUIRE(valid);

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

TEST_CASE("RSA-PSS-3072 - Modified Message Fails", "[rsa-pss][negative]") {
    RSAPSSKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::string message = "Original message";
    auto msg_bytes = utils::string_to_bytes(message);
    auto signature = sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes);

    std::string tampered = "Tampered message";
    auto tampered_bytes = utils::string_to_bytes(tampered);
    bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, tampered_bytes, signature);
    REQUIRE_FALSE(valid);

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

TEST_CASE("RSA-PSS-3072 - Modified Signature Fails", "[rsa-pss][negative]") {
    RSAPSSKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::string message = "Test message";
    auto msg_bytes = utils::string_to_bytes(message);
    auto signature = sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes);

    if (!signature.empty()) {
        signature[signature.size() - 1] ^= 0xFF;
    }
    bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes, signature);
    REQUIRE_FALSE(valid);

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

TEST_CASE("RSA-PSS-3072 - Wrong Key Fails", "[rsa-pss][negative]") {
    RSAPSSKeyFixture fixture1;
    ECDSAKeyFixture fixture2; // Different algorithm entirely

    void* priv_key1 = sig_engine::load_private_key(fixture1.priv_file, fixture1.algo);
    void* pub_key2 = sig_engine::load_public_key(fixture2.pub_file, fixture2.algo);

    std::string message = "Test message";
    auto msg_bytes = utils::string_to_bytes(message);
    auto signature = sig_engine::sign(priv_key1, fixture1.algo, sig_engine::HashAlgo::SHA256, msg_bytes);

    // Trying to verify RSA-PSS sig with an EC key should fail
    bool valid = sig_engine::verify(pub_key2, fixture2.algo, sig_engine::HashAlgo::SHA256, msg_bytes, signature);
    REQUIRE_FALSE(valid);

    sig_engine::free_key(priv_key1);
    sig_engine::free_key(pub_key2);
}

// ============================================================================
// Cross-Validation: ECDSA P-256 Message Size Tests
// ============================================================================

TEST_CASE("ECDSA P-256 - Large Message (1 MiB)", "[ecdsa][large]") {
    ECDSAKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);

    // Create 1 MiB message
    std::vector<uint8_t> large_msg(1024 * 1024, 0xAB);

    auto signature = sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, large_msg);
    REQUIRE(!signature.empty());

    bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, large_msg, signature);
    REQUIRE(valid);

    // Tamper and verify failure
    large_msg[0] ^= 0xFF;
    bool invalid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, large_msg, signature);
    REQUIRE_FALSE(invalid);

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

// ============================================================================
// Batch Verification
// ============================================================================

TEST_CASE("ECDSA P-256 - Batch Sign/Verify", "[ecdsa][batch]") {
    ECDSAKeyFixture fixture;
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);

    const int batch_size = 10;
    std::vector<std::vector<uint8_t>> messages;
    std::vector<std::vector<uint8_t>> signatures;

    // Create and sign multiple messages
    for (int i = 0; i < batch_size; i++) {
        std::string msg = "Message " + std::to_string(i);
        auto msg_bytes = utils::string_to_bytes(msg);
        messages.push_back(msg_bytes);
        signatures.push_back(sig_engine::sign(priv_key, fixture.algo, sig_engine::HashAlgo::SHA256, msg_bytes));
    }

    // Verify all
    for (int i = 0; i < batch_size; i++) {
        bool valid = sig_engine::verify(pub_key, fixture.algo, sig_engine::HashAlgo::SHA256, messages[i], signatures[i]);
        REQUIRE(valid);
    }

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);
}

// ============================================================================
// SHA256 Utility Tests
// ============================================================================

TEST_CASE("SHA-256 Hash", "[util][hash]") {
    std::string input = "test";
    auto input_bytes = utils::string_to_bytes(input);
    auto hash = utils::sha256(input_bytes);
    REQUIRE(hash.size() == 32); // SHA-256 is 32 bytes
}

TEST_CASE("SHA-384 Hash", "[util][hash]") {
    std::string input = "test";
    auto input_bytes = utils::string_to_bytes(input);
    auto hash = utils::sha384(input_bytes);
    REQUIRE(hash.size() == 48); // SHA-384 is 48 bytes
}

// ============================================================================
// Encoding Tests
// ============================================================================

TEST_CASE("Hex Encoding/Decoding Roundtrip", "[util][encode]") {
    std::vector<uint8_t> original = {0x00, 0xFF, 0xAB, 0xCD, 0x12, 0x34};
    std::string hex = utils::to_hex(original);
    REQUIRE(hex == "00ffabcd1234");
    auto decoded = utils::from_hex(hex);
    REQUIRE(decoded == original);
}

TEST_CASE("Base64 Encoding/Decoding Roundtrip", "[util][encode]") {
    std::vector<uint8_t> original = {'H', 'e', 'l', 'l', 'o'};
    std::string b64 = utils::to_base64(original);
    REQUIRE(b64 == "SGVsbG8=");
    auto decoded = utils::from_base64(b64);
    REQUIRE(decoded == original);
}

// ============================================================================
// DER Key Save/Load Tests
// ============================================================================

TEST_CASE("ECDSA P-256 - DER Key Format Roundtrip", "[ecdsa][der]") {
    ECDSAKeyFixture fixture;

    std::string pub_der = "test_ecdsa_pub.der";
    std::string priv_der = "test_ecdsa_priv.der";

    void* pub_key = sig_engine::load_public_key(fixture.pub_file, fixture.algo);
    void* priv_key = sig_engine::load_private_key(fixture.priv_file, fixture.algo);

    sig_engine::save_public_key_der(pub_key, fixture.algo, pub_der);
    sig_engine::save_private_key_der(priv_key, fixture.algo, priv_der);

    REQUIRE(fs::exists(pub_der));
    REQUIRE(fs::exists(priv_der));

    sig_engine::free_key(pub_key);
    sig_engine::free_key(priv_key);

    // Cleanup
    fs::remove(pub_der);
    fs::remove(priv_der);
}

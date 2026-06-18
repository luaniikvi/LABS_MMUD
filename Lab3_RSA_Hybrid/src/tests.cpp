#include <catch2/catch_amalgamated.hpp>
#include "rsa_engine.hpp"
#include "hybrid_engine.hpp"
#include "utils.hpp"
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>

using json = nlohmann::json;
using namespace lab3;

namespace fs = std::filesystem;

// Helper: resolve path relative to source file location (works from any cwd)
static std::string get_test_vectors_path() {
    fs::path src_dir = fs::path(__FILE__).parent_path();
    fs::path tv_dir = src_dir.parent_path() / "test_vectors";
    return tv_dir.string();
}

// Test fixtures
struct KeyPairFixture {
    std::string pub_file = "test_pub.pem";
    std::string priv_file = "test_priv.pem";
    std::string meta_file = "test_meta.json";
    int key_bits = 3072;

    KeyPairFixture() {
        rsa_engine::generate_keypair(key_bits, pub_file, priv_file, meta_file);
    }

    ~KeyPairFixture() {
        // Clean up test files
        try {
            fs::remove(pub_file);
            fs::remove(priv_file);
            fs::remove(meta_file);
        } catch (...) {}
    }
};

// ============================================================================
// RSA-OAEP Tests
// ============================================================================

TEST_CASE("RSA Key Generation - Valid Sizes", "[rsa][keygen]") {
    KeyPairFixture fixture_3072;
    REQUIRE(fs::exists(fixture_3072.pub_file));
    REQUIRE(fs::exists(fixture_3072.priv_file));
    
    auto pub_key = rsa_engine::load_public_key(fixture_3072.pub_file);
    REQUIRE(pub_key.GetModulus().BitCount() == 3072);
}

TEST_CASE("RSA Key Generation - Invalid Size", "[rsa][keygen][negative]") {
    REQUIRE_THROWS(rsa_engine::validate_key_size(2048));
    REQUIRE_THROWS(rsa_engine::validate_key_size(1024));
}

TEST_CASE("RSA-OAEP Encrypt/Decrypt - Small Message", "[rsa][encrypt]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::string plaintext = "Hello, RSA-OAEP!";
    auto pt_bytes = utils::string_to_bytes(plaintext);
    
    auto ciphertext = rsa_engine::encrypt(pub_key, pt_bytes);
    REQUIRE(!ciphertext.empty());
    
    auto decrypted = rsa_engine::decrypt(priv_key, ciphertext);
    REQUIRE(utils::bytes_to_string(decrypted) == plaintext);
}

TEST_CASE("RSA-OAEP Encrypt/Decrypt - Empty Message", "[rsa][encrypt]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::vector<uint8_t> empty;
    auto ciphertext = rsa_engine::encrypt(pub_key, empty);
    
    auto decrypted = rsa_engine::decrypt(priv_key, ciphertext);
    REQUIRE(decrypted.empty());
}

TEST_CASE("RSA-OAEP Encrypt/Decrypt - With Label", "[rsa][encrypt]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::string plaintext = "Message with label";
    std::string label = "TestLabel123";
    auto pt_bytes = utils::string_to_bytes(plaintext);
    
    auto ciphertext = rsa_engine::encrypt(pub_key, pt_bytes, label);
    auto decrypted = rsa_engine::decrypt(priv_key, ciphertext, label);
    
    REQUIRE(utils::bytes_to_string(decrypted) == plaintext);
}

TEST_CASE("RSA-OAEP - Max Plaintext Size", "[rsa][encrypt]") {
    size_t max_3072 = rsa_engine::get_max_plaintext_size(3072);
    REQUIRE(max_3072 == 318); // k - 2*hLen - 2 = 384 - 2*32 - 2 = 318 (SHA-256)
    
    size_t max_4096 = rsa_engine::get_max_plaintext_size(4096);
    REQUIRE(max_4096 == 446); // 512 - 2*32 - 2 = 446
}

// ============================================================================
// Negative Tests
// ============================================================================

TEST_CASE("RSA-OAEP - Wrong Key Decryption", "[rsa][negative]") {
    // Generate two separate keypairs with unique file paths
    std::string pub1 = "test_wrongkey_pub1.pem", priv1 = "test_wrongkey_priv1.pem", meta1 = "test_wrongkey_meta1.json";
    std::string pub2 = "test_wrongkey_pub2.pem", priv2 = "test_wrongkey_priv2.pem", meta2 = "test_wrongkey_meta2.json";
    
    rsa_engine::generate_keypair(3072, pub1, priv1, meta1);
    rsa_engine::generate_keypair(3072, pub2, priv2, meta2);
    
    auto pub_key1 = rsa_engine::load_public_key(pub1);
    auto priv_key2 = rsa_engine::load_private_key(priv2);
    
    std::string plaintext = "Secret message";
    auto pt_bytes = utils::string_to_bytes(plaintext);
    
    auto ciphertext = rsa_engine::encrypt(pub_key1, pt_bytes);
    
    // Decrypt with wrong private key should fail
    REQUIRE_THROWS(rsa_engine::decrypt(priv_key2, ciphertext));
    
    // Cleanup
    for (auto& f : {pub1, priv1, meta1, pub2, priv2, meta2}) fs::remove(f);
}

TEST_CASE("RSA-OAEP - Tampered Ciphertext", "[rsa][negative]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::string plaintext = "Do not tamper!";
    auto pt_bytes = utils::string_to_bytes(plaintext);
    
    auto ciphertext = rsa_engine::encrypt(pub_key, pt_bytes);
    
    // Tamper with ciphertext
    ciphertext[10] ^= 0xFF;
    
    REQUIRE_THROWS(rsa_engine::decrypt(priv_key, ciphertext));
}

TEST_CASE("RSA-OAEP - Plaintex Too Large", "[rsa][negative]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    
    size_t max_size = rsa_engine::get_max_plaintext_size(3072);
    std::vector<uint8_t> too_large(max_size + 1, 0xAA);
    
    REQUIRE_THROWS(rsa_engine::encrypt(pub_key, too_large));
}

TEST_CASE("RSA-OAEP - Invalid Ciphertext Length", "[rsa][negative]") {
    KeyPairFixture fixture;
    
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::vector<uint8_t> invalid_ct(100, 0x00);
    REQUIRE_THROWS(rsa_engine::decrypt(priv_key, invalid_ct));
}

// ============================================================================
// Hybrid Encryption Tests
// ============================================================================

TEST_CASE("Hybrid Encrypt/Decrypt - 1 KiB", "[hybrid][encrypt]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::vector<uint8_t> plaintext(1024, 0xAB);
    std::string env_file = "test_envelope.bin";
    std::string out_file = "test_output.bin";
    
    hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file);
    REQUIRE(fs::exists(env_file));
    
    hybrid_engine::decrypt_hybrid(priv_key, env_file, out_file);
    REQUIRE(fs::exists(out_file));
    
    auto decrypted = utils::read_file(out_file);
    REQUIRE(decrypted == plaintext);
    
    fs::remove(env_file);
    fs::remove(out_file);
}

TEST_CASE("Hybrid Encrypt/Decrypt - 1 MiB", "[hybrid][encrypt]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::vector<uint8_t> plaintext(1024 * 1024, 0xCD);
    std::string env_file = "test_envelope_1mb.bin";
    std::string out_file = "test_output_1mb.bin";
    
    hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file);
    hybrid_engine::decrypt_hybrid(priv_key, env_file, out_file);
    
    auto decrypted = utils::read_file(out_file);
    REQUIRE(decrypted == plaintext);
    
    fs::remove(env_file);
    fs::remove(out_file);
}

TEST_CASE("Hybrid Encrypt/Decrypt - With AAD", "[hybrid][encrypt]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::vector<uint8_t> plaintext = utils::string_to_bytes("Sensitive data");
    std::vector<uint8_t> aad = utils::string_to_bytes("Additional authenticated data");
    
    std::string env_file = "test_envelope_aad.bin";
    std::string out_file = "test_output_aad.bin";
    
    hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file, "", aad);
    hybrid_engine::decrypt_hybrid(priv_key, env_file, out_file);
    
    auto decrypted = utils::read_file(out_file);
    REQUIRE(decrypted == plaintext);
    
    fs::remove(env_file);
    fs::remove(out_file);
}

TEST_CASE("Hybrid - Tampered Ciphertext Detection", "[hybrid][negative]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::vector<uint8_t> plaintext(1024, 0xEF);
    std::string env_file = "test_envelope_tampered.bin";
    std::string out_file = "test_output_tampered.bin";
    
    hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file);
    
    // Tamper with the ciphertext portion
    auto file_data = utils::read_file(env_file);
    file_data[file_data.size() / 2] ^= 0xFF;
    utils::write_file(env_file, file_data);
    
    REQUIRE_THROWS(hybrid_engine::decrypt_hybrid(priv_key, env_file, out_file));
    
    fs::remove(env_file);
}

TEST_CASE("Hybrid - Wrong Private Key", "[hybrid][negative]") {
    // Generate two separate keypairs with unique file paths
    std::string pub1 = "test_hybwk_pub1.pem", priv1 = "test_hybwk_priv1.pem", meta1 = "test_hybwk_meta1.json";
    std::string pub2 = "test_hybwk_pub2.pem", priv2 = "test_hybwk_priv2.pem", meta2 = "test_hybwk_meta2.json";
    
    rsa_engine::generate_keypair(3072, pub1, priv1, meta1);
    rsa_engine::generate_keypair(3072, pub2, priv2, meta2);
    
    auto pub_key1 = rsa_engine::load_public_key(pub1);
    auto priv_key2 = rsa_engine::load_private_key(priv2);
    
    std::vector<uint8_t> plaintext(512, 0x12);
    std::string env_file = "test_envelope_wrong_key.bin";
    std::string out_file = "test_output_wrong_key.bin";
    
    hybrid_engine::encrypt_hybrid(pub_key1, plaintext, env_file);
    
    REQUIRE_THROWS(hybrid_engine::decrypt_hybrid(priv_key2, env_file, out_file));
    
    // Cleanup
    fs::remove(env_file);
    for (auto& f : {pub1, priv1, meta1, pub2, priv2, meta2}) fs::remove(f);
}

// ============================================================================
// KAT Runner Tests
// ============================================================================

TEST_CASE("KAT Runner - RSA-OAEP Vectors", "[kat][rsa]") {
    std::string kat_file = get_test_vectors_path() + "/rsa_oaep_kats.json";
    
    if (!fs::exists(kat_file)) {
        WARN("KAT file not found: " << kat_file);
        return;
    }
    
    std::string json_str = utils::read_text_file(kat_file);
    json kats = json::parse(json_str);
    
    KeyPairFixture fixture;
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test : kats["tests"]) {
        std::string desc = test["description"];
        std::vector<uint8_t> plaintext;
        std::string label = test.value("label", "");
        
        if (test.contains("plaintext")) {
            plaintext = utils::string_to_bytes(test["plaintext"]);
        } else if (test.contains("plaintext_hex")) {
            plaintext = utils::from_hex(test["plaintext_hex"]);
        } else if (test.contains("plaintext_size")) {
            plaintext = std::vector<uint8_t>(test["plaintext_size"], 0x42);
        }
        
        try {
            auto ciphertext = rsa_engine::encrypt(pub_key, plaintext, label);
            auto decrypted = rsa_engine::decrypt(priv_key, ciphertext, label);
            
            if (decrypted == plaintext) {
                INFO("PASS: " << desc);
                passed++;
            } else {
                INFO("FAIL: " << desc << " (decrypted mismatch)");
                failed++;
            }
        } catch (const std::exception& e) {
            INFO("FAIL: " << desc << " (" << e.what() << ")");
            failed++;
        }
    }
    
    std::cout << "\n=== RSA-OAEP KAT Summary ===" << std::endl;
    std::cout << "Passed: " << passed << "/" << (passed + failed) << std::endl;
    REQUIRE(failed == 0);
}

TEST_CASE("KAT Runner - Hybrid Encryption Vectors", "[kat][hybrid]") {
    std::string kat_file = get_test_vectors_path() + "/hybrid_kats.json";
    
    if (!fs::exists(kat_file)) {
        WARN("KAT file not found: " << kat_file);
        return;
    }
    
    std::string json_str = utils::read_text_file(kat_file);
    json kats = json::parse(json_str);
    
    KeyPairFixture fixture;
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test : kats["tests"]) {
        std::string desc = test["description"];
        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> aad;
        
        if (test.contains("plaintext_hex")) {
            plaintext = utils::from_hex(test["plaintext_hex"]);
        } else if (test.contains("plaintext_size")) {
            plaintext = std::vector<uint8_t>(test["plaintext_size"], 0x55);
        }
        
        if (test.contains("aad")) {
            aad = utils::string_to_bytes(test["aad"]);
        }
        
        long test_id = test["id"].get<long>();
        std::string env_file = "test_kat_env_" + std::to_string(test_id) + ".bin";
        std::string out_file = "test_kat_out_" + std::to_string(test_id) + ".bin";
        
        try {
            hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file, "", aad);
            hybrid_engine::decrypt_hybrid(priv_key, env_file, out_file);
            
            auto decrypted = utils::read_file(out_file);
            if (decrypted == plaintext) {
                INFO("PASS: " << desc);
                passed++;
            } else {
                INFO("FAIL: " << desc << " (size mismatch)");
                failed++;
            }
        } catch (const std::exception& e) {
            INFO("FAIL: " << desc << " (" << e.what() << ")");
            failed++;
        }
        
        fs::remove(env_file);
        fs::remove(out_file);
    }
    
    std::cout << "\n=== Hybrid Encryption KAT Summary ===" << std::endl;
    std::cout << "Passed: " << passed << "/" << (passed + failed) << std::endl;
    REQUIRE(failed == 0);
}

// ============================================================================
// Encoding Tests
// ============================================================================

TEST_CASE("Hex Encoding/Decoding", "[utils][encoding]") {
    std::vector<uint8_t> data = {0x00, 0x11, 0x22, 0xAB, 0xCD, 0xFF};
    std::string hex = utils::to_hex(data);
    REQUIRE(hex == "001122abcdff");
    
    auto decoded = utils::from_hex(hex);
    REQUIRE(decoded == data);
}

TEST_CASE("Base64 Encoding/Decoding", "[utils][encoding]") {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    std::string b64 = utils::to_base64(data);
    REQUIRE(b64 == "SGVsbG8=");
    
    auto decoded = utils::from_base64(b64);
    REQUIRE(decoded == data);
}

// ============================================================================
// File I/O Tests
// ============================================================================

TEST_CASE("File I/O - Binary", "[utils][io]") {
    std::string test_file = "test_io.bin";
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    
    utils::write_file(test_file, data);
    REQUIRE(fs::exists(test_file));
    
    auto read_data = utils::read_file(test_file);
    REQUIRE(read_data == data);
    
    fs::remove(test_file);
}

TEST_CASE("File I/O - Text", "[utils][io]") {
    std::string test_file = "test_io.txt";
    std::string text = "Hello, World! 你好世界";
    
    utils::write_text_file(test_file, text);
    REQUIRE(fs::exists(test_file));
    
    auto read_text = utils::read_text_file(test_file);
    REQUIRE(read_text == text);
    
    fs::remove(test_file);
}

// ============================================================================
// DER Format Tests
// ============================================================================

TEST_CASE("DER Format - Save and Load Roundtrip", "[rsa][der]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::string pub_der = "test_pub.der";
    std::string priv_der = "test_priv.der";
    
    // Save in DER format
    rsa_engine::save_public_key_der(pub_key, pub_der);
    rsa_engine::save_private_key_der(priv_key, priv_der);
    
    REQUIRE(fs::exists(pub_der));
    REQUIRE(fs::exists(priv_der));
    
    // Load from DER
    auto pub_key_der = rsa_engine::load_public_key_der(pub_der);
    auto priv_key_der = rsa_engine::load_private_key_der(priv_der);
    
    // Verify keys match
    REQUIRE(pub_key.GetModulus() == pub_key_der.GetModulus());
    REQUIRE(priv_key.GetModulus() == priv_key_der.GetModulus());
    
    // Verify encrypt/decrypt works with DER-loaded keys
    std::string msg = "DER format test";
    auto pt = utils::string_to_bytes(msg);
    auto ct = rsa_engine::encrypt(pub_key_der, pt);
    auto dec = rsa_engine::decrypt(priv_key_der, ct);
    REQUIRE(utils::bytes_to_string(dec) == msg);
    
    fs::remove(pub_der);
    fs::remove(priv_der);
}

// ============================================================================
// Additional Negative Tests (required by lab specification)
// ============================================================================

TEST_CASE("RSA-OAEP - Wrong Label Decryption Fails", "[rsa][negative][label]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::string plaintext = "Label-sensitive message";
    std::string encrypt_label = "CorrectLabel";
    std::string decrypt_label = "WrongLabel";
    
    auto pt_bytes = utils::string_to_bytes(plaintext);
    auto ciphertext = rsa_engine::encrypt(pub_key, pt_bytes, encrypt_label);
    
    // Decrypt with wrong label must fail (OAEP label is cryptographically bound)
    REQUIRE_THROWS(rsa_engine::decrypt(priv_key, ciphertext, decrypt_label));
}

TEST_CASE("Hybrid - Wrong OAEP Label Fails", "[hybrid][negative][label]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::vector<uint8_t> plaintext(2048, 0xAB); // Forces hybrid mode
    std::string env_file = "test_label_env.bin";
    std::string out_file = "test_label_out.bin";
    std::string label = "MyLabel";
    
    hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file, label);
    
    // Decrypt with wrong label must fail
    REQUIRE_THROWS(hybrid_engine::decrypt_hybrid(priv_key, env_file, out_file, "WrongLabel"));
    
    fs::remove(env_file);
}

TEST_CASE("Hybrid - Tampered Envelope Header Fails", "[hybrid][negative][header]") {
    KeyPairFixture fixture;
    
    auto pub_key = rsa_engine::load_public_key(fixture.pub_file);
    auto priv_key = rsa_engine::load_private_key(fixture.priv_file);
    
    std::vector<uint8_t> plaintext(1024, 0xEF);
    std::string env_file = "test_header_tamper.bin";
    std::string out_file = "test_header_out.bin";
    
    hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file);
    
    // Tamper with the envelope file data (corrupt the ciphertext portion)
    auto file_data = utils::read_file(env_file);
    // Corrupt a byte deep in the file (past the header, in ciphertext area)
    if (file_data.size() > 100) {
        file_data[file_data.size() - 10] ^= 0xFF;
        utils::write_file(env_file, file_data);
        
        // Decryption must fail with tampered data
        REQUIRE_THROWS(hybrid_engine::decrypt_hybrid(priv_key, env_file, out_file));
    }
    
    fs::remove(env_file);
}

TEST_CASE("Corrupted PEM Key File Rejected", "[rsa][negative][pem]") {
    std::string bad_pem = "corrupted_key.pem";
    
    // Write a corrupted PEM file with invalid base64
    std::string corrupt_content = 
        "-----BEGIN RSA PUBLIC KEY-----\n"
        "NOT_VALID_BASE64_KEY!!!\n"
        "-----END RSA PUBLIC KEY-----\n";
    utils::write_text_file(bad_pem, corrupt_content);
    
    REQUIRE_THROWS(rsa_engine::load_public_key_pem(bad_pem));
    
    fs::remove(bad_pem);
}

TEST_CASE("Malformed PEM - Missing Header Rejected", "[rsa][negative][pem]") {
    std::string bad_pem = "no_header.pem";
    
    // Write a file without PEM headers
    utils::write_text_file(bad_pem, "Just random text without PEM headers");
    
    REQUIRE_THROWS(rsa_engine::load_public_key_pem(bad_pem));
    REQUIRE_THROWS(rsa_engine::load_private_key_pem(bad_pem));
    
    fs::remove(bad_pem);
}

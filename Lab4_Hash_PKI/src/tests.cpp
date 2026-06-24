#include <catch2/catch_amalgamated.hpp>
#include "hash_engine.hpp"
#include "x509_parser.hpp"
#include "length_ext.hpp"
#include "utils.hpp"

#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <iostream>

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace lab4;

// Helper: resolve test_vectors path relative to source file
static std::string get_test_vectors_path() {
    fs::path src_dir = fs::path(__FILE__).parent_path();
    fs::path tv_dir = src_dir.parent_path() / "test_vectors";
    return tv_dir.string();
}

// Helper: hex string to bytes
static std::vector<uint8_t> H(const std::string& hex) {
    return utils::from_hex(hex);
}

// Helper: string to bytes
static std::vector<uint8_t> S(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// ============================================================================
// SHA-2 KAT Tests
// ============================================================================

TEST_CASE("SHA-2 Known Answer Tests", "[kat][sha2]") {
    std::string kat_file = get_test_vectors_path() + "/sha2_kats.json";
    if (!fs::exists(kat_file)) {
        WARN("KAT file not found: " << kat_file);
        return;
    }

    json kats = json::parse(utils::read_text_file(kat_file));

    for (const auto& test : kats["tests"]) {
        std::string algo_name = test["algo"].get<std::string>();
        std::string desc = test.value("description", "");

        auto algo = hash_engine::parse_algorithm(algo_name);

        std::vector<uint8_t> input;
        if (test.find("input_hex") != test.end()) {
            input = H(test["input_hex"].get<std::string>());
        } else {
            std::string s = test["input"].get<std::string>();
            input.assign(s.begin(), s.end());
        }

        auto digest = hash_engine::compute_hash(algo, input);
        std::string result = utils::to_hex(digest);
        std::string expected = test["expected_hex"].get<std::string>();

        // Normalize to lowercase
        auto to_lower = [](unsigned char c){ return static_cast<char>(std::tolower(c)); };
        std::transform(result.begin(), result.end(), result.begin(), to_lower);
        std::transform(expected.begin(), expected.end(), expected.begin(), to_lower);

        INFO("Test: " << desc);
        REQUIRE(result == expected);
    }
}

// ============================================================================
// SHA-3 KAT Tests
// ============================================================================

TEST_CASE("SHA-3 Known Answer Tests", "[kat][sha3]") {
    std::string kat_file = get_test_vectors_path() + "/sha3_kats.json";
    if (!fs::exists(kat_file)) {
        WARN("KAT file not found: " << kat_file);
        return;
    }

    json kats = json::parse(utils::read_text_file(kat_file));

    for (const auto& test : kats["tests"]) {
        std::string algo_name = test["algo"].get<std::string>();
        std::string desc = test.value("description", "");

        auto algo = hash_engine::parse_algorithm(algo_name);

        std::vector<uint8_t> input;
        std::string s = test["input"].get<std::string>();
        input.assign(s.begin(), s.end());

        std::vector<uint8_t> digest;
        if (algo == hash_engine::Algorithm::SHAKE128 ||
            algo == hash_engine::Algorithm::SHAKE256) {
            int outlen = test.value("outlen", 32);
            digest = hash_engine::compute_shake(algo, input, static_cast<size_t>(outlen));
        } else {
            digest = hash_engine::compute_hash(algo, input);
        }

        std::string result = utils::to_hex(digest);
        std::string expected = test["expected_hex"].get<std::string>();
        auto to_lower = [](unsigned char c){ return static_cast<char>(std::tolower(c)); };
        std::transform(result.begin(), result.end(), result.begin(), to_lower);
        std::transform(expected.begin(), expected.end(), expected.begin(), to_lower);

        INFO("Test: " << desc);
        REQUIRE(result == expected);
    }
}

// ============================================================================
// MD5 KAT Tests
// ============================================================================

TEST_CASE("MD5 Known Answer Tests (RFC 1321)", "[kat][md5]") {
    std::string kat_file = get_test_vectors_path() + "/md5_kats.json";
    if (!fs::exists(kat_file)) {
        WARN("KAT file not found: " << kat_file);
        return;
    }

    json kats = json::parse(utils::read_text_file(kat_file));

    for (const auto& test : kats["tests"]) {
        std::string desc = test.value("description", "");
        std::string s = test["input"].get<std::string>();
        std::vector<uint8_t> input(s.begin(), s.end());

        auto digest = hash_engine::compute_md5(input);
        std::string result = utils::to_hex(digest);
        std::string expected = test["expected_hex"].get<std::string>();
        auto to_lower = [](unsigned char c){ return static_cast<char>(std::tolower(c)); };
        std::transform(result.begin(), result.end(), result.begin(), to_lower);
        std::transform(expected.begin(), expected.end(), expected.begin(), to_lower);

        INFO("Test: " << desc);
        REQUIRE(result == expected);
    }
}

// ============================================================================
// HMAC KAT Tests (RFC 4231)
// ============================================================================

TEST_CASE("HMAC-SHA-256 RFC 4231 Test Cases", "[kat][hmac]") {
    SECTION("Test Case 1 - Basic") {
        auto key = H("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        auto data = S("Hi There");
        auto mac = hash_engine::compute_hmac(hash_engine::Algorithm::SHA256, key, data);
        std::string result = utils::to_hex(mac);
        REQUIRE(result == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    SECTION("Test Case 2 - Short key and data") {
        auto key = S("Jefe");
        auto data = S("what do ya want for nothing?");
        auto mac = hash_engine::compute_hmac(hash_engine::Algorithm::SHA256, key, data);
        std::string result = utils::to_hex(mac);
        REQUIRE(result == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    SECTION("Test Case 3 - 20-byte key, 50-byte data") {
        auto key = H("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        std::vector<uint8_t> data(50, 0xdd);
        auto mac = hash_engine::compute_hmac(hash_engine::Algorithm::SHA256, key, data);
        std::string result = utils::to_hex(mac);
        REQUIRE(result == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }
}

// ============================================================================
// Streaming vs In-Memory Consistency
// ============================================================================

TEST_CASE("Streaming hash matches in-memory hash", "[stream]") {
    // Create a temp file
    std::string tmp_file = "test_stream_temp.bin";
    std::vector<uint8_t> data(1024 * 100); // 100 KiB
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<uint8_t>(i & 0xFF);
    }
    utils::write_file(tmp_file, data);

    SECTION("SHA-256") {
        auto mem_hash = hash_engine::compute_hash(hash_engine::Algorithm::SHA256, data);
        auto stream_hash = hash_engine::compute_hash_stream(hash_engine::Algorithm::SHA256, tmp_file);
        REQUIRE(mem_hash == stream_hash);
    }

    SECTION("SHA-512") {
        auto mem_hash = hash_engine::compute_hash(hash_engine::Algorithm::SHA512, data);
        auto stream_hash = hash_engine::compute_hash_stream(hash_engine::Algorithm::SHA512, tmp_file);
        REQUIRE(mem_hash == stream_hash);
    }

    SECTION("SHA3-256") {
        auto mem_hash = hash_engine::compute_hash(hash_engine::Algorithm::SHA3_256, data);
        auto stream_hash = hash_engine::compute_hash_stream(hash_engine::Algorithm::SHA3_256, tmp_file);
        REQUIRE(mem_hash == stream_hash);
    }

    fs::remove(tmp_file);
}

// ============================================================================
// SHAKE Tests
// ============================================================================

TEST_CASE("SHAKE variable output", "[shake]") {
    auto data = S("");

    SECTION("SHAKE128 default 32 bytes") {
        auto digest = hash_engine::compute_shake(hash_engine::Algorithm::SHAKE128, data, 32);
        REQUIRE(digest.size() == 32);
    }

    SECTION("SHAKE128 custom 64 bytes") {
        auto digest = hash_engine::compute_shake(hash_engine::Algorithm::SHAKE128, data, 64);
        REQUIRE(digest.size() == 64);
    }

    SECTION("SHAKE256 custom 16 bytes") {
        auto digest = hash_engine::compute_shake(hash_engine::Algorithm::SHAKE256, data, 16);
        REQUIRE(digest.size() == 16);
    }
}

// ============================================================================
// Negative Tests
// ============================================================================

TEST_CASE("Negative tests", "[negative]") {
    SECTION("Invalid algorithm name") {
        REQUIRE_THROWS(hash_engine::parse_algorithm("invalid_algo"));
    }

    SECTION("Non-existent file") {
        REQUIRE_THROWS(hash_engine::compute_hash_stream(
            hash_engine::Algorithm::SHA256, "nonexistent_file.bin"));
    }

    SECTION("SHAKE with non-SHAKE algo") {
        std::vector<uint8_t> data = {0x01, 0x02};
        REQUIRE_THROWS(hash_engine::compute_shake(
            hash_engine::Algorithm::SHA256, data, 32));
    }

    SECTION("HMAC with unsupported algorithm") {
        std::vector<uint8_t> key = {0x01};
        std::vector<uint8_t> data = {0x02};
        REQUIRE_THROWS(hash_engine::compute_hmac(
            hash_engine::Algorithm::MD5, key, data));
    }
}

// ============================================================================
// Length-Extension Attack Tests
// ============================================================================

TEST_CASE("Length-extension attack on H(k||m)", "[length_ext]") {
    SECTION("Basic extension") {
        std::vector<uint8_t> key = S("secret_key_1234");  // 14 bytes
        std::vector<uint8_t> message = S("hello");         // 5 bytes

        // Compute naive MAC
        auto mac = length_ext::compute_mac(key, message);
        REQUIRE(mac.size() == 32);

        // Extend with new data
        auto append = S("&admin=true");
        auto result = length_ext::extend_mac(mac, key.size(), message.size(), append);

        // Verify: forged MAC should match SHA-256(key || original_msg || padding || append)
        // We construct the full message: message + padding + append
        std::vector<uint8_t> full_forged = message;
        full_forged.insert(full_forged.end(), result.forged_message.begin(), result.forged_message.end());

        bool valid = length_ext::verify_extension(key, full_forged, result.forged_mac);
        REQUIRE(valid);
    }

    SECTION("Different key lengths") {
        for (size_t klen : {8, 16, 32}) {
            std::vector<uint8_t> key(klen, 0xAA);
            std::vector<uint8_t> message = S("test_data");

            auto mac = length_ext::compute_mac(key, message);
            auto append = S("extra");
            auto result = length_ext::extend_mac(mac, klen, message.size(), append);

            std::vector<uint8_t> full_forged = message;
            full_forged.insert(full_forged.end(), result.forged_message.begin(), result.forged_message.end());

            bool valid = length_ext::verify_extension(key, full_forged, result.forged_mac);
            INFO("Key length: " << klen);
            REQUIRE(valid);
        }
    }
}

// ============================================================================
// MD5 Collision Demo
// ============================================================================

TEST_CASE("MD5 collision demo files", "[md5_collision]") {
    std::string dir = get_test_vectors_path();
    dir = fs::path(dir).parent_path().string() + "/demo/md5_collision";

    std::string file_a = dir + "/collision_a.bin";
    std::string file_b = dir + "/collision_b.bin";

    if (!fs::exists(file_a) || !fs::exists(file_b)) {
        WARN("MD5 collision files not found in: " << dir);
        return;
    }

    auto data_a = utils::read_file(file_a);
    auto data_b = utils::read_file(file_b);

    auto md5_a = hash_engine::compute_md5(data_a);
    auto md5_b = hash_engine::compute_md5(data_b);

    // MD5 should match (collision)
    REQUIRE(md5_a == md5_b);

    // SHA-256 should differ
    auto sha256_a = hash_engine::compute_hash(hash_engine::Algorithm::SHA256, data_a);
    auto sha256_b = hash_engine::compute_hash(hash_engine::Algorithm::SHA256, data_b);
    REQUIRE(sha256_a != sha256_b);
}

// ============================================================================
// Utility Tests
// ============================================================================

TEST_CASE("Utility encoding", "[utils]") {
    SECTION("Hex roundtrip") {
        std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
        std::string hex = utils::to_hex(data);
        auto decoded = utils::from_hex(hex);
        REQUIRE(data == decoded);
    }

    SECTION("Base64 roundtrip") {
        std::vector<uint8_t> data = S("Hello, World!");
        std::string b64 = utils::to_base64(data);
        auto decoded = utils::from_base64(b64);
        REQUIRE(data == decoded);
    }

    SECTION("Hex case insensitive") {
        auto a = utils::from_hex("AABBCC");
        auto b = utils::from_hex("aabbcc");
        REQUIRE(a == b);
    }

    SECTION("File I/O roundtrip") {
        std::string tmp = "test_utils_temp.bin";
        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
        utils::write_file(tmp, data);
        auto loaded = utils::read_file(tmp);
        REQUIRE(data == loaded);
        fs::remove(tmp);
    }
}

// ============================================================================
// X.509 Certificate Tests (requires test cert)
// ============================================================================

TEST_CASE("X.509 certificate parsing", "[x509]") {
    // Generate a self-signed test cert using openssl if available
    std::string cert_file = "test_cert.pem";
    std::string key_file = "test_key.pem";

    // Try to find a test cert in the project
    std::string cert_path = get_test_vectors_path();
    cert_path = fs::path(cert_path).parent_path().string() + "/demo/test_cert.pem";

    if (!fs::exists(cert_path)) {
        // Try to generate one
        int ret = std::system(
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 "
            "-keyout test_key.pem -out test_cert.pem -days 1 -nodes "
            "-subj \"/CN=Test/O=Lab4\" 2>nul"
        );
        if (ret != 0 || !fs::exists("test_cert.pem")) {
            WARN("Cannot generate test certificate (openssl not available)");
            return;
        }
        cert_path = "test_cert.pem";
    }

    auto info = x509::parse_certificate(cert_path);

    REQUIRE(!info.subject.empty());
    REQUIRE(!info.issuer.empty());
    REQUIRE(!info.public_key_algo.empty());
    REQUIRE(info.version >= 1);

    std::string formatted = x509::format_cert_info(info);
    REQUIRE(!formatted.empty());

    // Self-signed: verify with own public key
    // (For self-signed, subject == issuer and signature verifies with own key)
    if (fs::exists("test_key.pem")) {
        fs::remove("test_cert.pem");
        fs::remove("test_key.pem");
    }
}

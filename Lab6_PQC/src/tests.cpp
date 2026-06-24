#include <catch2/catch_amalgamated.hpp>
#include "pq_engine.hpp"
#include "utils.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace lab6;

namespace fs = std::filesystem;

// ============================================================================
// Test Fixtures
// ============================================================================

struct MLDSAKeyFixture {
    std::string pub_file = "test_mldsa_pub.pem";
    std::string priv_file = "test_mldsa_priv.pem";
    pq_engine::PQAlgo algo = pq_engine::PQAlgo::ML_DSA_44;

    MLDSAKeyFixture() { pq_engine::generate_keypair(algo, pub_file, priv_file); }
    ~MLDSAKeyFixture() { cleanup(pub_file, priv_file); }

    static void cleanup(const std::string& pub, const std::string& priv) {
        try {
            fs::remove(pub); fs::remove(priv);
            auto pd = pub; size_t d = pd.find_last_of('.'); if (d != std::string::npos) pd = pd.substr(0, d) + ".der";
            auto rd = priv; d = rd.find_last_of('.'); if (d != std::string::npos) rd = rd.substr(0, d) + ".der";
            fs::remove(pd); fs::remove(rd);
        } catch (...) {}
    }
};

struct MLKEMKeyFixture {
    std::string pub_file = "test_kem_pub.pem";
    std::string priv_file = "test_kem_priv.pem";
    pq_engine::PQAlgo algo = pq_engine::PQAlgo::ML_KEM_512;

    MLKEMKeyFixture() { pq_engine::generate_keypair(algo, pub_file, priv_file); }
    ~MLKEMKeyFixture() { MLDSAKeyFixture::cleanup(pub_file, priv_file); }
};

// ============================================================================
// Algorithm Parsing Tests
// ============================================================================

TEST_CASE("Algorithm Parsing", "[pq][parse]") {
    REQUIRE(pq_engine::parse_algo("mldsa-44") == pq_engine::PQAlgo::ML_DSA_44);
    REQUIRE(pq_engine::parse_algo("mldsa-65") == pq_engine::PQAlgo::ML_DSA_65);
    REQUIRE(pq_engine::parse_algo("mlkem-512") == pq_engine::PQAlgo::ML_KEM_512);
    REQUIRE_THROWS(pq_engine::parse_algo("invalid"));
}

// ============================================================================
// ML-DSA-44 Tests
// ============================================================================

TEST_CASE("ML-DSA-44 Key Generation", "[mldsa][keygen]") {
    MLDSAKeyFixture fixture;
    REQUIRE(fs::exists(fixture.pub_file));
    REQUIRE(fs::exists(fixture.priv_file));
    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);
    REQUIRE(pub_key != nullptr);
    pq_engine::free_key(pub_key);
}

TEST_CASE("ML-DSA-44 Sign/Verify", "[mldsa][sign]") {
    MLDSAKeyFixture fixture;
    void* priv_key = pq_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::string msg = "Hello ML-DSA!";
    auto msg_bytes = utils::string_to_bytes(msg);
    auto sig = pq_engine::sign(priv_key, fixture.algo, pq_engine::HashAlgo::SHA256, msg_bytes);
    REQUIRE(!sig.empty());

    bool valid = pq_engine::verify(pub_key, fixture.algo, pq_engine::HashAlgo::SHA256, msg_bytes, sig);
    REQUIRE(valid);

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
}

TEST_CASE("ML-DSA-44 - Modified Message Fails", "[mldsa][negative]") {
    MLDSAKeyFixture fixture;
    void* priv_key = pq_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::string msg = "Test";
    auto mb = utils::string_to_bytes(msg);
    auto sig = pq_engine::sign(priv_key, fixture.algo, pq_engine::HashAlgo::SHA256, mb);

    auto tampered = utils::string_to_bytes("Tampered");
    bool valid = pq_engine::verify(pub_key, fixture.algo, pq_engine::HashAlgo::SHA256, tampered, sig);
    REQUIRE_FALSE(valid);

    // Also test modified signature
    if (!sig.empty()) {
        sig[sig.size() - 1] ^= 0xFF;
        bool valid2 = pq_engine::verify(pub_key, fixture.algo, pq_engine::HashAlgo::SHA256, mb, sig);
        REQUIRE_FALSE(valid2);
    }

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
}

TEST_CASE("ML-DSA-44 - Large Message", "[mldsa][large]") {
    MLDSAKeyFixture fixture;
    void* priv_key = pq_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);

    std::vector<uint8_t> large(1024 * 1024, 0xAB);
    auto sig = pq_engine::sign(priv_key, fixture.algo, pq_engine::HashAlgo::SHA256, large);
    REQUIRE(!sig.empty());
    bool valid = pq_engine::verify(pub_key, fixture.algo, pq_engine::HashAlgo::SHA256, large, sig);
    REQUIRE(valid);

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
}

TEST_CASE("ML-DSA-44 - Batch Verify", "[mldsa][batch]") {
    MLDSAKeyFixture fixture;
    void* priv_key = pq_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);

    for (int i = 0; i < 10; i++) {
        auto mb = utils::string_to_bytes("Batch msg " + std::to_string(i));
        auto sig = pq_engine::sign(priv_key, fixture.algo, pq_engine::HashAlgo::SHA256, mb);
        bool valid = pq_engine::verify(pub_key, fixture.algo, pq_engine::HashAlgo::SHA256, mb, sig);
        REQUIRE(valid);
    }

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
}

// ============================================================================
// ML-DSA-65 Tests
// ============================================================================

TEST_CASE("ML-DSA-65 Sign/Verify", "[mldsa65][sign]") {
    std::string pub = "test_dsa65_pub.pem", priv = "test_dsa65_priv.pem";
    pq_engine::generate_keypair(pq_engine::PQAlgo::ML_DSA_65, pub, priv);

    void* priv_key = pq_engine::load_private_key(priv, pq_engine::PQAlgo::ML_DSA_65);
    void* pub_key = pq_engine::load_public_key(pub, pq_engine::PQAlgo::ML_DSA_65);

    auto mb = utils::string_to_bytes("Hello ML-DSA-65!");
    auto sig = pq_engine::sign(priv_key, pq_engine::PQAlgo::ML_DSA_65, pq_engine::HashAlgo::SHA256, mb);
    REQUIRE(!sig.empty());
    bool valid = pq_engine::verify(pub_key, pq_engine::PQAlgo::ML_DSA_65, pq_engine::HashAlgo::SHA256, mb, sig);
    REQUIRE(valid);

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
    MLDSAKeyFixture::cleanup(pub, priv);
}

// ============================================================================
// ML-KEM-512 Tests
// ============================================================================

TEST_CASE("ML-KEM-512 Key Generation", "[mlkem][keygen]") {
    MLKEMKeyFixture fixture;
    REQUIRE(fs::exists(fixture.pub_file));
    REQUIRE(fs::exists(fixture.priv_file));
    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);
    REQUIRE(pub_key != nullptr);
    pq_engine::free_key(pub_key);
}

TEST_CASE("ML-KEM-512 Encaps/Decaps Roundtrip", "[mlkem][kem]") {
    MLKEMKeyFixture fixture;
    void* priv_key = pq_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);

    auto [ct, ss1] = pq_engine::encapsulate(pub_key, fixture.algo);
    REQUIRE(!ct.empty());
    REQUIRE(!ss1.empty());

    auto ss2 = pq_engine::decapsulate(priv_key, fixture.algo, ct);
    REQUIRE(ss1 == ss2);

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
}

TEST_CASE("ML-KEM-512 - Tampered Ciphertext Fails", "[mlkem][negative]") {
    MLKEMKeyFixture fixture;
    void* priv_key = pq_engine::load_private_key(fixture.priv_file, fixture.algo);
    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);

    auto [ct, ss1] = pq_engine::encapsulate(pub_key, fixture.algo);

    // Tamper ciphertext
    if (!ct.empty()) ct[ct.size() / 2] ^= 0xFF;

    auto ss2 = pq_engine::decapsulate(priv_key, fixture.algo, ct);
    REQUIRE(ss1 != ss2);

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
}

// ============================================================================
// DER Key Format Test
// ============================================================================

TEST_CASE("ML-DSA-44 DER Key Roundtrip", "[mldsa][der]") {
    MLDSAKeyFixture fixture;
    std::string pub_der = "test_der_pub.der", priv_der = "test_der_priv.der";

    void* pub_key = pq_engine::load_public_key(fixture.pub_file, fixture.algo);
    void* priv_key = pq_engine::load_private_key(fixture.priv_file, fixture.algo);
    pq_engine::save_public_key_der(pub_key, fixture.algo, pub_der);
    pq_engine::save_private_key_der(priv_key, fixture.algo, priv_der);

    REQUIRE(fs::exists(pub_der));
    REQUIRE(fs::exists(priv_der));

    pq_engine::free_key(pub_key);
    pq_engine::free_key(priv_key);
    fs::remove(pub_der); fs::remove(priv_der);
}

// ============================================================================
// PQ Certificate Test
// ============================================================================

TEST_CASE("PQ Certificate Sign/Verify", "[cert]") {
    // Generate CA and subject keys
    std::string ca_pub = "cert_ca_pub.pem", ca_priv = "cert_ca_priv.pem";
    std::string sub_pub = "cert_sub_pub.pem", sub_priv = "cert_sub_priv.pem";

    pq_engine::generate_keypair(pq_engine::PQAlgo::ML_DSA_44, ca_pub, ca_priv);
    pq_engine::generate_keypair(pq_engine::PQAlgo::ML_DSA_44, sub_pub, sub_priv);

    // Read subject public key
    auto sub_pub_data = utils::read_text_file(sub_pub);

    // Create certificate structure
    json cert;
    cert["subject"] = "Alice";
    cert["public_key"] = utils::to_base64(std::vector<uint8_t>(sub_pub_data.begin(), sub_pub_data.end()));
    cert["issuer"] = "PQ-CA";
    cert["algorithm"] = "ML-DSA-44";

    // Sign with CA key
    void* ca_priv_key = pq_engine::load_private_key(ca_priv, pq_engine::PQAlgo::ML_DSA_44);
    std::string tbs = "Alice" + sub_pub_data;
    auto tbs_bytes = std::vector<uint8_t>(tbs.begin(), tbs.end());
    auto signature = pq_engine::sign(ca_priv_key, pq_engine::PQAlgo::ML_DSA_44, pq_engine::HashAlgo::SHA256, tbs_bytes);
    pq_engine::free_key(ca_priv_key);
    cert["signature"] = utils::to_hex(signature);

    // Now verify
    void* ca_pub_key = pq_engine::load_public_key(ca_pub, pq_engine::PQAlgo::ML_DSA_44);
    auto sig2 = utils::from_hex(cert["signature"]);
    bool valid = pq_engine::verify(ca_pub_key, pq_engine::PQAlgo::ML_DSA_44, pq_engine::HashAlgo::SHA256, tbs_bytes, sig2);
    REQUIRE(valid);

    // Tamper test
    auto tampered_tbs = std::vector<uint8_t>(tbs_bytes.size(), 0x00);
    bool invalid = pq_engine::verify(ca_pub_key, pq_engine::PQAlgo::ML_DSA_44, pq_engine::HashAlgo::SHA256, tampered_tbs, sig2);
    REQUIRE_FALSE(invalid);

    pq_engine::free_key(ca_pub_key);
    MLDSAKeyFixture::cleanup(ca_pub, ca_priv);
    MLDSAKeyFixture::cleanup(sub_pub, sub_priv);
}

// ============================================================================
// Utility Tests
// ============================================================================

TEST_CASE("Encoding Roundtrip", "[util]") {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    REQUIRE(utils::from_hex(utils::to_hex(data)) == data);
    REQUIRE(utils::from_base64(utils::to_base64(data)) == data);
}

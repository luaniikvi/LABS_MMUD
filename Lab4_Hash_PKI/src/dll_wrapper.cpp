#include "hash_engine.hpp"
#include "x509_parser.hpp"
#include "length_ext.hpp"
#include "utils.hpp"
#include "../include/dll_export.hpp"

#include <nlohmann/json.hpp>
#include <sstream>
#include <cstring>
#include <filesystem>

using json = nlohmann::json;
namespace fs = std::filesystem;

static thread_local char g_error_buf[1024] = {0};
static thread_local char g_result_buf[65536] = {0};

static void set_error(const char* msg) {
    std::strncpy(g_error_buf, msg, sizeof(g_error_buf) - 1);
    g_error_buf[sizeof(g_error_buf) - 1] = '\0';
}

static const char* set_result(const std::string& s) {
    std::strncpy(g_result_buf, s.c_str(), sizeof(g_result_buf) - 1);
    g_result_buf[sizeof(g_result_buf) - 1] = '\0';
    return g_result_buf;
}

extern "C" {

// ============================================================================
// Hash
// ============================================================================

DLL_EXPORT int lab4_hash(const char* algo, const uint8_t* data, int data_len,
                         char* out_hex, int out_hex_len, const char* err_msg) {
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        auto digest = lab4::hash_engine::compute_hash(a, data, static_cast<size_t>(data_len));
        std::string hex = lab4::utils::to_hex(digest);
        if (out_hex && out_hex_len > 0) {
            std::strncpy(out_hex, hex.c_str(), out_hex_len - 1);
            out_hex[out_hex_len - 1] = '\0';
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

DLL_EXPORT int lab4_hash_file(const char* algo, const char* filepath, int stream_mode,
                              char* out_hex, int out_hex_len, const char* err_msg) {
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        std::vector<uint8_t> digest;
        if (stream_mode) {
            digest = lab4::hash_engine::compute_hash_stream(a, filepath);
        } else {
            auto data = lab4::utils::read_file(filepath);
            digest = lab4::hash_engine::compute_hash(a, data);
        }
        std::string hex = lab4::utils::to_hex(digest);
        if (out_hex && out_hex_len > 0) {
            std::strncpy(out_hex, hex.c_str(), out_hex_len - 1);
            out_hex[out_hex_len - 1] = '\0';
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

// ============================================================================
// SHAKE
// ============================================================================

DLL_EXPORT int lab4_shake(const char* algo, const uint8_t* data, int data_len,
                          int outlen, char* out_hex, int out_hex_len, const char* err_msg) {
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        auto digest = lab4::hash_engine::compute_shake(a, data, static_cast<size_t>(data_len),
                                                        static_cast<size_t>(outlen));
        std::string hex = lab4::utils::to_hex(digest);
        if (out_hex && out_hex_len > 0) {
            std::strncpy(out_hex, hex.c_str(), out_hex_len - 1);
            out_hex[out_hex_len - 1] = '\0';
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

// ============================================================================
// HMAC
// ============================================================================

DLL_EXPORT int lab4_hmac(const char* algo, const uint8_t* key, int key_len,
                         const uint8_t* data, int data_len,
                         char* out_hex, int out_hex_len, const char* err_msg) {
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        auto mac = lab4::hash_engine::compute_hmac(a, key, static_cast<size_t>(key_len),
                                                     data, static_cast<size_t>(data_len));
        std::string hex = lab4::utils::to_hex(mac);
        if (out_hex && out_hex_len > 0) {
            std::strncpy(out_hex, hex.c_str(), out_hex_len - 1);
            out_hex[out_hex_len - 1] = '\0';
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

// ============================================================================
// X.509
// ============================================================================

DLL_EXPORT int lab4_parse_x509(const char* cert_path, char* out_json, int out_json_len,
                               const char* err_msg) {
    try {
        auto info = lab4::x509::parse_certificate(cert_path);
        json j;
        j["subject"] = info.subject;
        j["issuer"] = info.issuer;
        j["public_key_algo"] = info.public_key_algo;
        j["public_key_params"] = info.public_key_params;
        j["signature_algo"] = info.signature_algo;
        j["not_before"] = info.not_before;
        j["not_after"] = info.not_after;
        j["key_usage"] = info.key_usage;
        j["san_entries"] = info.san_entries;
        j["serial_number"] = info.serial_number;
        j["fingerprint_sha256"] = info.fingerprint_sha256;
        j["version"] = info.version;

        std::string json_str = j.dump(2);
        if (out_json && out_json_len > 0) {
            std::strncpy(out_json, json_str.c_str(), out_json_len - 1);
            out_json[out_json_len - 1] = '\0';
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

DLL_EXPORT int lab4_verify_x509(const char* cert_path, const char* issuer_key_path,
                                const char* err_msg) {
    try {
        bool valid = lab4::x509::verify_signature(cert_path, issuer_key_path);
        return valid ? 1 : 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

// ============================================================================
// Length-Extension Attack
// ============================================================================

DLL_EXPORT int lab4_length_ext(const char* mac_hex, int key_len, int msg_len,
                               const char* append_data, char* out_json, int out_json_len,
                               const char* err_msg) {
    try {
        auto original_mac = lab4::utils::from_hex(mac_hex);
        std::vector<uint8_t> append(append_data, append_data + std::strlen(append_data));

        auto result = lab4::length_ext::extend_mac(
            original_mac, static_cast<size_t>(key_len),
            static_cast<size_t>(msg_len), append);

        json j;
        j["forged_mac"] = lab4::utils::to_hex(result.forged_mac);
        j["forged_message_hex"] = lab4::utils::to_hex(result.forged_message);
        j["padding_hex"] = result.padding_hex;

        std::string json_str = j.dump(2);
        if (out_json && out_json_len > 0) {
            std::strncpy(out_json, json_str.c_str(), out_json_len - 1);
            out_json[out_json_len - 1] = '\0';
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

// ============================================================================
// MD5 Demo
// ============================================================================

DLL_EXPORT int lab4_md5_demo(const char* dir_path, char* out_json, int out_json_len,
                             const char* err_msg) {
    try {
        std::string dir = dir_path;
        std::string file_a = dir + "/collision_a.bin";
        std::string file_b = dir + "/collision_b.bin";

        auto data_a = lab4::utils::read_file(file_a);
        auto data_b = lab4::utils::read_file(file_b);

        auto md5_a = lab4::hash_engine::compute_md5(data_a);
        auto md5_b = lab4::hash_engine::compute_md5(data_b);
        auto sha256_a = lab4::hash_engine::compute_hash(lab4::hash_engine::Algorithm::SHA256, data_a);
        auto sha256_b = lab4::hash_engine::compute_hash(lab4::hash_engine::Algorithm::SHA256, data_b);

        json j;
        j["file_a"] = {
            {"path", file_a}, {"size", data_a.size()},
            {"md5", lab4::utils::to_hex(md5_a)},
            {"sha256", lab4::utils::to_hex(sha256_a)}
        };
        j["file_b"] = {
            {"path", file_b}, {"size", data_b.size()},
            {"md5", lab4::utils::to_hex(md5_b)},
            {"sha256", lab4::utils::to_hex(sha256_b)}
        };
        j["md5_match"] = (md5_a == md5_b);
        j["sha256_match"] = (sha256_a == sha256_b);

        std::string json_str = j.dump(2);
        if (out_json && out_json_len > 0) {
            std::strncpy(out_json, json_str.c_str(), out_json_len - 1);
            out_json[out_json_len - 1] = '\0';
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

// ============================================================================
// KAT Runner
// ============================================================================

DLL_EXPORT const char* lab4_run_kat(const char* vectors_file, const char* err_msg) {
    try {
        std::string filepath = vectors_file;
        if (!lab4::utils::file_exists(filepath)) {
            set_error("KAT file not found");
            return nullptr;
        }

        std::string json_str = lab4::utils::read_text_file(filepath);
        json kats = json::parse(json_str);

        std::ostringstream oss;
        int passed = 0, failed = 0;

        for (const auto& test : kats["tests"]) {
            std::string algo_name = test.value("algo", "sha256");
            auto algo = lab4::hash_engine::parse_algorithm(algo_name);

            std::vector<uint8_t> input;
            if (test.contains("input_hex")) {
                input = lab4::utils::from_hex(test["input_hex"].get<std::string>());
            } else {
                std::string s = test["input"].get<std::string>();
                input.assign(s.begin(), s.end());
            }

            std::vector<uint8_t> digest;
            if (algo == lab4::hash_engine::Algorithm::SHAKE128 ||
                algo == lab4::hash_engine::Algorithm::SHAKE256) {
                int outlen = test.value("outlen", 32);
                digest = lab4::hash_engine::compute_shake(algo, input, static_cast<size_t>(outlen));
            } else {
                digest = lab4::hash_engine::compute_hash(algo, input);
            }

            std::string result = lab4::utils::to_hex(digest);
            std::string expected = test["expected_hex"].get<std::string>();
            std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            std::transform(expected.begin(), expected.end(), expected.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

            if (result == expected) {
                oss << "[PASS] " << test.value("description", "") << "\n";
                passed++;
            } else {
                oss << "[FAIL] " << test.value("description", "") << "\n";
                oss << "  Expected: " << expected << "\n  Got:      " << result << "\n";
                failed++;
            }
        }

        oss << "\nTOTAL: " << (passed + failed) << "\n";
        oss << "PASSED: " << passed << "\n";
        oss << "FAILED: " << failed << "\n";

        return set_result(oss.str());
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

// ============================================================================
// Free
// ============================================================================

DLL_EXPORT void lab4_free_string(const char* s) {
    (void)s; // static buffers, no-op
}

} // extern "C"

#define _CRT_SECURE_NO_WARNINGS
#include "../include/dll_export.hpp"
#include "hash_engine.hpp"
#include "x509_parser.hpp"
#include "length_ext.hpp"
#include "utils.hpp"

#include <nlohmann/json.hpp>
#include <cstring>
#include <sstream>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>


#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

using json = nlohmann::json;

static thread_local char g_error_buf[1024] = {0};
static thread_local char g_result_buf[65536] = {0};

static void set_error(const char* msg) {
    std::strncpy(g_error_buf, msg, sizeof(g_error_buf) - 1);
    g_error_buf[sizeof(g_error_buf) - 1] = '\0';
}

static void set_result(const std::string& s) {
    std::strncpy(g_result_buf, s.c_str(), sizeof(g_result_buf) - 1);
    g_result_buf[sizeof(g_result_buf) - 1] = '\0';
}

static void copy_to_buf(char* out, int out_len, const std::string& s) {
    if (out && out_len > 0) {
        std::strncpy(out, s.c_str(), static_cast<size_t>(out_len) - 1);
        out[static_cast<size_t>(out_len) - 1] = '\0';
    }
}

extern "C" {

DLL_EXPORT int lab4_hash(const char* algo, const uint8_t* data, int data_len,
                         char* out_hex, int out_hex_len, char* err_buf, int err_buf_len) {
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        auto digest = lab4::hash_engine::compute_hash(a, data, static_cast<size_t>(data_len));
        std::string hex = lab4::utils::to_hex(digest);
        copy_to_buf(out_hex, out_hex_len, hex);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_hash_file(const char* algo, const char* filepath, int stream_mode,
                              char* out_hex, int out_hex_len, char* err_buf, int err_buf_len) {
    (void)err_buf; (void)err_buf_len;
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
        copy_to_buf(out_hex, out_hex_len, hex);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_shake(const char* algo, const uint8_t* data, int data_len,
                          int outlen, char* out_hex, int out_hex_len, char* err_buf, int err_buf_len) {
    (void)err_buf; (void)err_buf_len;
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        auto digest = lab4::hash_engine::compute_shake(a, data, static_cast<size_t>(data_len),
                                                        static_cast<size_t>(outlen));
        std::string hex = lab4::utils::to_hex(digest);
        copy_to_buf(out_hex, out_hex_len, hex);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_shake_file(const char* algo, const char* filepath, int stream_mode,
                               int outlen, char* out_hex, int out_hex_len, char* err_buf, int err_buf_len) {
    (void)stream_mode; (void)err_buf; (void)err_buf_len;
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        std::vector<uint8_t> digest;
        if (stream_mode) {
            digest = lab4::hash_engine::compute_shake_stream(a, filepath, static_cast<size_t>(outlen));
        } else {
            auto data = lab4::utils::read_file(filepath);
            digest = lab4::hash_engine::compute_shake(a, data, static_cast<size_t>(outlen));
        }
        std::string hex = lab4::utils::to_hex(digest);
        copy_to_buf(out_hex, out_hex_len, hex);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_hmac(const char* algo, const uint8_t* key, int key_len,
                         const uint8_t* data, int data_len,
                         char* out_hex, int out_hex_len, char* err_buf, int err_buf_len) {
    (void)err_buf; (void)err_buf_len;
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        auto mac = lab4::hash_engine::compute_hmac(a, key, static_cast<size_t>(key_len),
                                                     data, static_cast<size_t>(data_len));
        std::string hex = lab4::utils::to_hex(mac);
        copy_to_buf(out_hex, out_hex_len, hex);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_hmac_file(const char* algo, const uint8_t* key, int key_len,
                              const char* filepath, int stream_mode,
                              char* out_hex, int out_hex_len, char* err_buf, int err_buf_len) {
    (void)stream_mode; (void)err_buf; (void)err_buf_len;
    try {
        auto a = lab4::hash_engine::parse_algorithm(algo);
        std::vector<uint8_t> key_vec(key, key + key_len);
        auto mac = lab4::hash_engine::compute_hmac_stream(a, key_vec, filepath);
        std::string hex = lab4::utils::to_hex(mac);
        copy_to_buf(out_hex, out_hex_len, hex);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_parse_x509(const char* cert_path, char* out_json, int out_json_len,
                               char* err_buf, int err_buf_len) {
    (void)err_buf; (void)err_buf_len;
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
        copy_to_buf(out_json, out_json_len, json_str);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_verify_x509(const char* cert_path, const char* issuer_pub_path,
                                char* err_buf, int err_buf_len) {
    (void)err_buf; (void)err_buf_len;
    try {
        bool valid = lab4::x509::verify_signature(cert_path, issuer_pub_path);
        return valid ? 1 : 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_length_ext(const char* mac_hex, int key_len, int msg_len,
                               const char* append_data, char* out_json, int out_json_len,
                               char* err_buf, int err_buf_len) {
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
        copy_to_buf(out_json, out_json_len, json_str);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int lab4_md5_demo(const char* dir_path, char* out_json, int out_json_len,
                             char* err_buf, int err_buf_len) {
    try {
        std::string file_a = std::string(dir_path) + "/collision_a.bin";
        std::string file_b = std::string(dir_path) + "/collision_b.bin";

        auto data_a = lab4::utils::read_file(file_a);
        auto data_b = lab4::utils::read_file(file_b);

        auto md5_a = lab4::hash_engine::compute_md5(data_a);
        auto md5_b = lab4::hash_engine::compute_md5(data_b);
        auto sha256_a = lab4::hash_engine::compute_hash(lab4::hash_engine::Algorithm::SHA256, data_a);
        auto sha256_b = lab4::hash_engine::compute_hash(lab4::hash_engine::Algorithm::SHA256, data_b);

        json j;
        j["file_a"] = {
            {"path", file_a},
            {"size", data_a.size()},
            {"md5", lab4::utils::to_hex(md5_a)},
            {"sha256", lab4::utils::to_hex(sha256_a)}
        };
        j["file_b"] = {
            {"path", file_b},
            {"size", data_b.size()},
            {"md5", lab4::utils::to_hex(md5_b)},
            {"sha256", lab4::utils::to_hex(sha256_b)}
        };
        j["md5_match"] = (md5_a == md5_b);
        j["sha256_match"] = (sha256_a == sha256_b);

        std::string json_str = j.dump(2);
        copy_to_buf(out_json, out_json_len, json_str);
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT const char* lab4_run_kat(const char* vectors_file, char* err_buf, int err_buf_len) {
    (void)err_buf; (void)err_buf_len;
    try {
        if (!lab4::utils::file_exists(vectors_file)) {
            set_error("KAT file not found");
            return nullptr;
        }

        std::string text = lab4::utils::read_text_file(vectors_file);
        json kats = json::parse(text);

        std::ostringstream oss;
        int passed = 0;
        int failed = 0;

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

            std::string got = lab4::utils::to_hex(digest);
            std::string expected = test["expected_hex"].get<std::string>();

            if (got == expected) {
                oss << "[PASS] " << test.value("description", "") << "\n";
                ++passed;
            } else {
                oss << "[FAIL] " << test.value("description", "") << "\n"
                    << "  Expected: " << expected << "\n"
                    << "  Got:      " << got << "\n";
                ++failed;
            }
        }

        oss << "\nTOTAL: " << (passed + failed) << "\n"
            << "PASSED: " << passed << "\n"
            << "FAILED: " << failed << "\n";

        set_result(oss.str());
        return g_result_buf;
    } catch (const std::exception& e) {
        set_error(e.what());
        if (err_buf && err_buf_len > 0) {
            std::strncpy(err_buf, g_error_buf, static_cast<size_t>(err_buf_len) - 1);
            err_buf[err_buf_len - 1] = '\0';
        }
        return nullptr;
    }
}

DLL_EXPORT void lab4_free_string(const char* s) {
    (void)s;
}

} // extern "C"

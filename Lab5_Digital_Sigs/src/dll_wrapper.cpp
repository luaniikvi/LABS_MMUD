// dll_wrapper.cpp - DLL exports for Lab 5
#include "dll_export.hpp"
#include "sig_engine.hpp"
#include "utils.hpp"
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>

using namespace lab5;

// Thread-local storage for error messages and results
static thread_local char g_error_msg[1024];
static thread_local std::string g_result_buffer;
static thread_local std::string g_test_output;
static thread_local std::string g_kat_output;

extern "C" {

DLL_EXPORT int lab5_keygen(
    const char* algo,
    const char* pub_file,
    const char* priv_file,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        auto sig_algo = sig_engine::parse_algo(algo);
        sig_engine::generate_keypair(sig_algo, pub_file, priv_file);
        return 0;
    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return -1;
    }
}

DLL_EXPORT const char* lab5_sign(
    const char* algo,
    const char* hash_algo,
    const char* priv_key_file,
    const char* message,
    int msg_len,
    const char* output_file,
    int encode_mode,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        auto sig_algo = sig_engine::parse_algo(algo);
        auto hash = sig_engine::parse_hash(hash_algo);

        if (!utils::file_exists(priv_key_file)) {
            std::string msg = "Private key file not found: " + std::string(priv_key_file);
            strncpy_s(error_msg, 1024, msg.c_str(), 1023);
            error_msg[1023] = '\0';
            return nullptr;
        }

        void* priv_key = sig_engine::load_private_key(priv_key_file, sig_algo);
        std::vector<uint8_t> msg(message, message + msg_len);
        auto signature = sig_engine::sign(priv_key, sig_algo, hash, msg);
        sig_engine::free_key(priv_key);

        // Write signature file
        if (output_file && strlen(output_file) > 0) {
            utils::write_file(output_file, signature);
        }

        g_result_buffer = utils::encode_output(signature, static_cast<utils::EncodeMode>(encode_mode));
        return g_result_buffer.c_str();

    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT int lab5_verify(
    const char* algo,
    const char* hash_algo,
    const char* pub_key_file,
    const char* message,
    int msg_len,
    const char* sig_file,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        auto sig_algo = sig_engine::parse_algo(algo);
        auto hash = sig_engine::parse_hash(hash_algo);

        if (!utils::file_exists(pub_key_file)) {
            std::string msg = "Public key file not found: " + std::string(pub_key_file);
            strncpy_s(error_msg, 1024, msg.c_str(), 1023);
            error_msg[1023] = '\0';
            return -1;
        }

        void* pub_key = sig_engine::load_public_key(pub_key_file, sig_algo);
        std::vector<uint8_t> msg_bytes(message, message + msg_len);
        auto signature = utils::read_file(sig_file);

        bool valid = sig_engine::verify(pub_key, sig_algo, hash, msg_bytes, signature);
        sig_engine::free_key(pub_key);

        return valid ? 1 : 0;

    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return -1;
    }
}

DLL_EXPORT const char* lab5_sign_file(
    const char* algo,
    const char* hash_algo,
    const char* priv_key_file,
    const char* input_file,
    const char* output_file,
    int encode_mode,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        auto sig_algo = sig_engine::parse_algo(algo);
        auto hash = sig_engine::parse_hash(hash_algo);

        if (!utils::file_exists(priv_key_file)) {
            std::string msg = "Private key file not found: " + std::string(priv_key_file);
            strncpy_s(error_msg, 1024, msg.c_str(), 1023);
            error_msg[1023] = '\0';
            return nullptr;
        }

        void* priv_key = sig_engine::load_private_key(priv_key_file, sig_algo);
        auto msg = utils::read_file(input_file);
        auto signature = sig_engine::sign(priv_key, sig_algo, hash, msg);
        sig_engine::free_key(priv_key);

        if (output_file && strlen(output_file) > 0) {
            utils::write_file(output_file, signature);
        }

        g_result_buffer = utils::encode_output(signature, static_cast<utils::EncodeMode>(encode_mode));
        return g_result_buffer.c_str();

    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT int lab5_verify_file(
    const char* algo,
    const char* hash_algo,
    const char* pub_key_file,
    const char* input_file,
    const char* sig_file,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        auto sig_algo = sig_engine::parse_algo(algo);
        auto hash = sig_engine::parse_hash(hash_algo);

        if (!utils::file_exists(pub_key_file)) {
            std::string msg = "Public key file not found: " + std::string(pub_key_file);
            strncpy_s(error_msg, 1024, msg.c_str(), 1023);
            error_msg[1023] = '\0';
            return -1;
        }

        void* pub_key = sig_engine::load_public_key(pub_key_file, sig_algo);
        auto msg = utils::read_file(input_file);
        auto signature = utils::read_file(sig_file);

        bool valid = sig_engine::verify(pub_key, sig_algo, hash, msg, signature);
        sig_engine::free_key(pub_key);

        return valid ? 1 : 0;

    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return -1;
    }
}

DLL_EXPORT const char* lab5_run_benchmark(
    const char* /*mode_filter*/,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        std::ostringstream oss;
        oss << "=== Digital Signature Benchmark (Lab 5) ===" << std::endl;
        oss << "Note: Full benchmark requires CLI tool: benchmark" << std::endl;

        g_result_buffer = oss.str();
        return g_result_buffer.c_str();

    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT const char* lab5_run_tests(
    int* total,
    int* passed,
    int* failed,
    char* error_msg
) {
    try {
        g_test_output.clear();
        *total = 0;
        *passed = 0;
        *failed = 0;

        std::ostringstream oss;
        oss << "=== Digital Signature Basic Validation Tests (Lab 5) ===" << std::endl;

        // Test 1: ECDSA P-256 key generation
        try {
            std::string pub_file = "dll_test_ecdsa_pub.pem";
            std::string priv_file = "dll_test_ecdsa_priv.pem";
            sig_engine::generate_keypair(sig_engine::SigAlgo::ECDSA_P256, pub_file, priv_file);

            void* pub_key = sig_engine::load_public_key(pub_file, sig_engine::SigAlgo::ECDSA_P256);
            if (pub_key && sig_engine::get_key_size(pub_key, sig_engine::SigAlgo::ECDSA_P256) == 256) {
                oss << "[PASS] ECDSA P-256 key generation" << std::endl;
                (*passed)++;
            } else {
                oss << "[FAIL] ECDSA P-256 key generation" << std::endl;
                (*failed)++;
            }
            sig_engine::free_key(pub_key);
            std::remove(pub_file.c_str());
            std::remove(priv_file.c_str());
        } catch (...) {
            oss << "[FAIL] ECDSA P-256 key generation - exception" << std::endl;
            (*failed)++;
        }

        // Test 2: ECDSA P-256 sign/verify
        try {
            std::string pub_file = "dll_test_ecdsa_pub2.pem";
            std::string priv_file = "dll_test_ecdsa_priv2.pem";
            sig_engine::generate_keypair(sig_engine::SigAlgo::ECDSA_P256, pub_file, priv_file);

            void* priv_key = sig_engine::load_private_key(priv_file, sig_engine::SigAlgo::ECDSA_P256);
            void* pub_key = sig_engine::load_public_key(pub_file, sig_engine::SigAlgo::ECDSA_P256);

            std::string msg = "Hello ECDSA!";
            auto msg_bytes = utils::string_to_bytes(msg);
            auto sig = sig_engine::sign(priv_key, sig_engine::SigAlgo::ECDSA_P256, sig_engine::HashAlgo::SHA256, msg_bytes);
            bool valid = sig_engine::verify(pub_key, sig_engine::SigAlgo::ECDSA_P256, sig_engine::HashAlgo::SHA256, msg_bytes, sig);

            sig_engine::free_key(priv_key);
            sig_engine::free_key(pub_key);
            std::remove(pub_file.c_str());
            std::remove(priv_file.c_str());

            if (valid) {
                oss << "[PASS] ECDSA P-256 sign/verify" << std::endl;
                (*passed)++;
            } else {
                oss << "[FAIL] ECDSA P-256 sign/verify" << std::endl;
                (*failed)++;
            }
        } catch (...) {
            oss << "[FAIL] ECDSA P-256 sign/verify - exception" << std::endl;
            (*failed)++;
        }

        // Test 3: RSA-PSS-3072 key generation
        try {
            std::string pub_file = "dll_test_rsa_pub.pem";
            std::string priv_file = "dll_test_rsa_priv.pem";
            sig_engine::generate_keypair(sig_engine::SigAlgo::RSA_PSS_3072, pub_file, priv_file);

            void* pub_key = sig_engine::load_public_key(pub_file, sig_engine::SigAlgo::RSA_PSS_3072);
            if (pub_key && sig_engine::get_key_size(pub_key, sig_engine::SigAlgo::RSA_PSS_3072) >= 3072) {
                oss << "[PASS] RSA-PSS-3072 key generation" << std::endl;
                (*passed)++;
            } else {
                oss << "[FAIL] RSA-PSS-3072 key generation" << std::endl;
                (*failed)++;
            }
            sig_engine::free_key(pub_key);
            std::remove(pub_file.c_str());
            std::remove(priv_file.c_str());
        } catch (...) {
            oss << "[FAIL] RSA-PSS-3072 key generation - exception" << std::endl;
            (*failed)++;
        }

        // Test 4: RSA-PSS-3072 sign/verify
        try {
            std::string pub_file = "dll_test_rsa_pub2.pem";
            std::string priv_file = "dll_test_rsa_priv2.pem";
            sig_engine::generate_keypair(sig_engine::SigAlgo::RSA_PSS_3072, pub_file, priv_file);

            void* priv_key = sig_engine::load_private_key(priv_file, sig_engine::SigAlgo::RSA_PSS_3072);
            void* pub_key = sig_engine::load_public_key(pub_file, sig_engine::SigAlgo::RSA_PSS_3072);

            std::string msg = "Hello RSA-PSS!";
            auto msg_bytes = utils::string_to_bytes(msg);
            auto sig = sig_engine::sign(priv_key, sig_engine::SigAlgo::RSA_PSS_3072, sig_engine::HashAlgo::SHA256, msg_bytes);
            bool valid = sig_engine::verify(pub_key, sig_engine::SigAlgo::RSA_PSS_3072, sig_engine::HashAlgo::SHA256, msg_bytes, sig);

            sig_engine::free_key(priv_key);
            sig_engine::free_key(pub_key);
            std::remove(pub_file.c_str());
            std::remove(priv_file.c_str());

            if (valid) {
                oss << "[PASS] RSA-PSS-3072 sign/verify" << std::endl;
                (*passed)++;
            } else {
                oss << "[FAIL] RSA-PSS-3072 sign/verify" << std::endl;
                (*failed)++;
            }
        } catch (...) {
            oss << "[FAIL] RSA-PSS-3072 sign/verify - exception" << std::endl;
            (*failed)++;
        }

        *total = *passed + *failed;
        oss << std::endl << "Results: " << *passed << "/" << *total << " passed" << std::endl;

        g_test_output = oss.str();
        return g_test_output.c_str();

    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT const char* lab5_run_kat(
    const char* vectors_file,
    char* error_msg
) {
    try {
        g_kat_output.clear();
        std::ostringstream oss;
        oss << "=== Digital Signature KAT Validation (Lab 5) ===" << std::endl;
        oss << "Vectors file: " << vectors_file << std::endl;

        std::ifstream check(vectors_file);
        if (!check.good()) {
            oss << "[ERROR] File not found: " << vectors_file << std::endl;
        } else {
            oss << "[INFO] Full KAT validation requires CLI: sigtool --kat " << vectors_file << std::endl;
        }

        g_kat_output = oss.str();
        return g_kat_output.c_str();

    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT void lab5_free_string(const char* /*str*/) {
    // No-op for static buffer
}

} // extern "C"

// dll_wrapper.cpp - DLL exports for Lab 3
#include "dll_export.hpp"
#include "rsa_engine.hpp"
#include "hybrid_engine.hpp"
#include "utils.hpp"
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>

using namespace lab3;

// Thread-local storage for error messages and results
static thread_local char g_error_msg[1024];
static thread_local std::string g_result_buffer;

extern "C" {

DLL_EXPORT int lab3_keygen(
    int bits,
    const char* pub_file,
    const char* priv_file,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        
        std::string meta_file = std::string(pub_file) + "_meta.json";
        
        rsa_engine::generate_keypair(bits, pub_file, priv_file, meta_file);
        
        return 0; // Success
        
    } catch (const std::exception& e) {
        strncpy(error_msg, e.what(), 1023);
        error_msg[1023] = '\0';
        return -1; // Error
    }
}

DLL_EXPORT const char* lab3_encrypt(
    const char* pub_key_file,
    const char* plaintext,
    const char* label,
    const char* aad_hex,
    const char* output_file,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        
        // Load public key
        auto pub_key = rsa_engine::load_public_key(pub_key_file);
        
        // Convert plaintext
        std::vector<uint8_t> pt(plaintext, plaintext + strlen(plaintext));
        
        // Parse AAD
        std::vector<uint8_t> aad;
        if (aad_hex && strlen(aad_hex) > 0) {
            aad = utils::from_hex(aad_hex);
        }
        
        std::string lbl = label ? label : "";
        
        // Check if hybrid mode needed
        size_t max_size = rsa_engine::get_max_plaintext_size(pub_key.GetModulus().BitCount());
        
        if (pt.size() <= max_size && aad.empty()) {
            // Direct RSA-OAEP
            auto ciphertext = rsa_engine::encrypt(pub_key, pt, lbl);
            
            // Write to file
            utils::write_file(output_file, ciphertext);
            
            g_result_buffer = utils::to_hex(ciphertext);
            return g_result_buffer.c_str();
        } else {
            // Hybrid encryption
            hybrid_engine::encrypt_hybrid(pub_key, pt, output_file, lbl, aad);
            g_result_buffer = "Hybrid envelope written to: " + std::string(output_file);
            return g_result_buffer.c_str();
        }
        
    } catch (const std::exception& e) {
        strncpy(error_msg, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT int lab3_decrypt(
    const char* priv_key_file,
    const char* input_file,
    const char* label,
    const char* output_file,
    char* error_msg
) {
    try {
        g_error_msg[0] = '\0';
        
        // Load private key
        auto priv_key = rsa_engine::load_private_key(priv_key_file);
        
        std::string lbl = label ? label : "";
        
        // Try hybrid first
        try {
            hybrid_engine::decrypt_hybrid(priv_key, input_file, output_file, lbl);
        } catch (...) {
            // Fallback to direct RSA-OAEP
            auto ciphertext = utils::read_file(input_file);
            auto plaintext = rsa_engine::decrypt(priv_key, ciphertext, lbl);
            utils::write_file(output_file, plaintext);
        }
        
        return 0; // Success
        
    } catch (const std::exception& e) {
        strncpy(error_msg, e.what(), 1023);
        error_msg[1023] = '\0';
        return -1; // Error
    }
}

DLL_EXPORT void lab3_free_string(const char* str) {
    // No-op for static buffer
}

// Thread-local buffers for benchmark/test/kat output
static thread_local std::string g_bench_output;
static thread_local std::string g_test_output;
static thread_local std::string g_kat_output;

DLL_EXPORT const char* lab3_run_benchmark(
    const char* mode_filter,
    char* error_msg
) {
    try {
        g_bench_output.clear();
        
        std::ostringstream oss;
        std::streambuf* old_cout = std::cout.rdbuf(oss.rdbuf());
        std::streambuf* old_cerr = std::cerr.rdbuf(oss.rdbuf());
        
        using namespace std;
        
        oss << "=== RSA-OAEP & Hybrid Benchmark ===" << endl;
        oss << "Note: Full benchmark requires CLI tool: rsatool_bench.exe" << endl;
        
        std::cout.rdbuf(old_cout);
        std::cerr.rdbuf(old_cerr);
        
        g_bench_output = oss.str();
        return g_bench_output.c_str();
        
    } catch (const std::exception& e) {
        strncpy(error_msg, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT const char* lab3_run_tests(
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
        std::streambuf* old_cout = std::cout.rdbuf(oss.rdbuf());
        std::streambuf* old_cerr = std::cerr.rdbuf(oss.rdbuf());
        
        using namespace std;
        using namespace lab3;
        
        oss << "=== RSA Basic Validation Tests ===" << endl;
        
        // Test 1: RSA key generation
        try {
            std::string pub_file = "dll_test_pub.pem";
            std::string priv_file = "dll_test_priv.pem";
            std::string meta_file = "dll_test_meta.json";
            
            rsa_engine::generate_keypair(2048, pub_file, priv_file, meta_file);
            
            auto pub_key = rsa_engine::load_public_key_pem(pub_file);
            if (pub_key) {
                oss << "[PASS] RSA-2048 key generation" << endl;
                (*passed)++;
            } else {
                oss << "[FAIL] RSA-2048 key generation" << endl;
                (*failed)++;
            }
            
            // Cleanup
            remove(pub_file.c_str());
            remove(priv_file.c_str());
            remove(meta_file.c_str());
        } catch (...) {
            oss << "[FAIL] RSA-2048 key generation - exception" << endl;
            (*failed)++;
        }
        
        // Test 2: RSA-OAEP encrypt/decrypt
        try {
            std::string pub_file = "dll_test_pub.pem";
            std::string priv_file = "dll_test_priv.pem";
            std::string meta_file = "dll_test_meta.json";
            
            rsa_engine::generate_keypair(2048, pub_file, priv_file, meta_file);
            
            auto pub_key = rsa_engine::load_public_key_pem(pub_file);
            auto priv_key = rsa_engine::load_private_key_pem(priv_file);
            
            std::string plaintext = "Hello RSA-OAEP!";
            auto ciphertext = rsa_engine::encrypt(pub_key, plaintext);
            auto decrypted = rsa_engine::decrypt(priv_key, ciphertext);
            
            if (decrypted == plaintext) {
                oss << "[PASS] RSA-OAEP encrypt/decrypt" << endl;
                (*passed)++;
            } else {
                oss << "[FAIL] RSA-OAEP encrypt/decrypt" << endl;
                (*failed)++;
            }
            
            // Cleanup
            remove(pub_file.c_str());
            remove(priv_file.c_str());
            remove(meta_file.c_str());
        } catch (...) {
            oss << "[FAIL] RSA-OAEP encrypt/decrypt - exception" << endl;
            (*failed)++;
        }
        
        *total = *passed + *failed;
        oss << endl << "Results: " << *passed << "/" << *total << " passed" << endl;
        
        std::cout.rdbuf(old_cout);
        std::cerr.rdbuf(old_cerr);
        
        g_test_output = oss.str();
        return g_test_output.c_str();
        
    } catch (const std::exception& e) {
        strncpy(error_msg, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT const char* lab3_run_kat(
    const char* vectors_file,
    char* error_msg
) {
    try {
        g_kat_output.clear();
        
        std::ostringstream oss;
        std::streambuf* old_cout = std::cout.rdbuf(oss.rdbuf());
        std::streambuf* old_cerr = std::cerr.rdbuf(oss.rdbuf());
        
        using namespace std;
        
        oss << "=== RSA KAT Validation ===" << endl;
        oss << "Vectors file: " << vectors_file << endl;
        
        if (!utils::file_exists(vectors_file)) {
            oss << "[ERROR] File not found: " << vectors_file << endl;
        } else {
            oss << "[INFO] Full KAT validation requires CLI: rsatool.exe --kat " << vectors_file << endl;
        }
        
        std::cout.rdbuf(old_cout);
        std::cerr.rdbuf(old_cerr);
        
        g_kat_output = oss.str();
        return g_kat_output.c_str();
        
    } catch (const std::exception& e) {
        strncpy(error_msg, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

} // extern "C"

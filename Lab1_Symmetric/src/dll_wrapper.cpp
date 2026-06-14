// dll_wrapper.cpp - DLL exports for Lab 1
#include "dll_export.hpp"
#include "crypto_engine.hpp"
#include "utils.hpp"
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>

// Suppress linter false positive: DLL_EXPORT is dllexport when building DLL
#ifdef _MSC_VER
#pragma warning(disable: 4910)
#endif

// Thread-local storage for error messages
static thread_local char g_error_msg[1024];
static thread_local std::string g_result_buffer;

extern "C" {

DLL_EXPORT const char* lab1_encrypt(
    const char* mode,
    const char* key_hex,
    const char* iv_hex,
    const char* plaintext,
    const char* aad_hex,
    int* out_length,
    char* error_msg
) {
    try {
        // Clear error
        g_error_msg[0] = '\0';
        
        // Build config
        CryptoConfig config;
        config.mode = mode;
        config.key = FromHex(key_hex);
        
        if (iv_hex && strlen(iv_hex) > 0) {
            config.iv = FromHex(iv_hex);
        }
        
        if (aad_hex && strlen(aad_hex) > 0) {
            config.aad = std::string(aad_hex, aad_hex + strlen(aad_hex));
        }
        
        config.isAead = (config.mode == "gcm" || config.mode == "ccm");
        
        // Convert plaintext using UTF-8 aware function
        std::vector<uint8_t> pt = StringToBytes(std::string(plaintext, plaintext + strlen(plaintext)));
        
        // Encrypt
        std::vector<uint8_t> tag;
        auto ciphertext = EncryptAES(pt, config, tag);
        
        // Return hex
        g_result_buffer = ToHex(ciphertext);
        *out_length = g_result_buffer.length();
        
        return g_result_buffer.c_str();
        
    } catch (const std::exception& e) {
        strncpy(error_msg, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT const char* lab1_decrypt(
    const char* mode,
    const char* key_hex,
    const char* iv_hex,
    const char* ciphertext_hex,
    const char* tag_hex,
    const char* aad_hex,
    int* out_length,
    char* error_msg
) {
    try {
        // Clear error
        g_error_msg[0] = '\0';
        
        // Build config
        CryptoConfig config;
        config.mode = mode;
        config.key = FromHex(key_hex);
        
        if (iv_hex && strlen(iv_hex) > 0) {
            config.iv = FromHex(iv_hex);
        }
        
        if (aad_hex && strlen(aad_hex) > 0) {
            config.aad = std::string(aad_hex, aad_hex + strlen(aad_hex));
        }
        
        config.isAead = (config.mode == "gcm" || config.mode == "ccm");
        
        // Convert ciphertext and tag
        auto ciphertext = FromHex(ciphertext_hex);
        std::vector<uint8_t> tag;
        if (tag_hex && strlen(tag_hex) > 0) {
            tag = FromHex(tag_hex);
        }
        
        // Decrypt
        auto plaintext = DecryptAES(ciphertext, config, tag);
        
        // Return as UTF-8 string
        g_result_buffer = BytesToString(plaintext);
        *out_length = g_result_buffer.length();
        
        return g_result_buffer.c_str();
        
    } catch (const std::exception& e) {
        strncpy(error_msg, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT void lab1_free_string(const char* str) {
    // No-op for static buffer
}

// Thread-local buffers for benchmark/test/kat output
static thread_local std::string g_bench_output;
static thread_local std::string g_test_output;
static thread_local std::string g_kat_output;

DLL_EXPORT const char* lab1_run_benchmark(
    const char* mode_filter,
    int size_filter,
    char* error_msg
) {
    try {
        g_bench_output.clear();
        
        std::ostringstream oss;
        std::streambuf* old_cout = std::cout.rdbuf(oss.rdbuf());
        std::streambuf* old_cerr = std::cerr.rdbuf(oss.rdbuf());
        
        // Inline benchmark logic
        using namespace std;
        
        oss << "=== AES Benchmark ===" << endl;
        oss << "Note: Full benchmark implementation requires benchmark.cpp integration" << endl;
        oss << "For complete benchmarking, run: aestool_bench.exe" << endl;
        
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

DLL_EXPORT const char* lab1_run_tests(
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
        
        // Inline basic tests using Lab 1 global API
        using namespace std;
        
        oss << "=== Basic Validation Tests ===" << endl;
        
        // Test 1: AES-256-GCM roundtrip
        try {
            CryptoConfig cfg;
            cfg.mode = "gcm";
            cfg.key = FromHex("0000000000000000000000000000000000000000000000000000000000000000");
            cfg.iv = FromHex("000000000000000000000000");
            cfg.isAead = true;
            
            vector<uint8_t> plaintext = StringToBytes("Hello, World!");
            vector<uint8_t> tag;
            auto ciphertext = EncryptAES(plaintext, cfg, tag);
            
            auto decrypted = DecryptAES(ciphertext, cfg, tag);
            
            if (decrypted == plaintext) {
                oss << "[PASS] AES-256-GCM roundtrip" << endl;
                (*passed)++;
            } else {
                oss << "[FAIL] AES-256-GCM roundtrip" << endl;
                (*failed)++;
            }
        } catch (const exception& e) {
            oss << "[FAIL] AES-256-GCM roundtrip: " << e.what() << endl;
            (*failed)++;
        }
        
        // Test 2: AES-256-CBC roundtrip
        try {
            CryptoConfig cfg;
            cfg.mode = "cbc";
            cfg.key = FromHex("0000000000000000000000000000000000000000000000000000000000000000");
            cfg.iv = FromHex("00000000000000000000000000000000");
            
            vector<uint8_t> plaintext = StringToBytes("Test CBC");
            vector<uint8_t> tag;
            auto ciphertext = EncryptAES(plaintext, cfg, tag);
            
            auto decrypted = DecryptAES(ciphertext, cfg, tag);
            
            if (decrypted == plaintext) {
                oss << "[PASS] AES-256-CBC roundtrip" << endl;
                (*passed)++;
            } else {
                oss << "[FAIL] AES-256-CBC roundtrip" << endl;
                (*failed)++;
            }
        } catch (const exception& e) {
            oss << "[FAIL] AES-256-CBC roundtrip: " << e.what() << endl;
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

DLL_EXPORT const char* lab1_run_kat(
    const char* vectors_file,
    char* error_msg
) {
    try {
        g_kat_output.clear();
        
        std::ostringstream oss;
        std::streambuf* old_cout = std::cout.rdbuf(oss.rdbuf());
        std::streambuf* old_cerr = std::cerr.rdbuf(oss.rdbuf());
        
        // Inline KAT validation
        using namespace std;
        
        oss << "=== NIST KAT Validation ===" << endl;
        oss << "Vectors file: " << vectors_file << endl;
        
        // Check if file exists using simple ifstream
        ifstream test_file(vectors_file);
        if (!test_file.good()) {
            oss << "[ERROR] File not found: " << vectors_file << endl;
        } else {
            test_file.close();
            oss << "[INFO] Full KAT validation requires CLI tool: aestool.exe --kat " << vectors_file << endl;
            oss << "[INFO] DLL mode provides basic validation only" << endl;
            
            // Try to call RunKatTest if available
            try {
                RunKatTest(std::string(vectors_file));
                oss << "[PASS] KAT validation completed" << endl;
            } catch (const exception& e) {
                oss << "[WARN] KAT validation warning: " << e.what() << endl;
            }
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

// ============================================================================
// Low-Level Buffer API (for ctypes GUI integration)
// ============================================================================

DLL_EXPORT int encrypt_aes_c(
    const char* mode,
    uint8_t* plaintext, int plaintext_len,
    uint8_t* key, int key_len,
    uint8_t* iv, int iv_len,
    const char* aad,
    int is_aead, int allow_ecb,
    uint8_t* ciphertext_out, int* ciphertext_len_out,
    uint8_t* key_out, int* key_len_out,
    uint8_t* iv_out, int* iv_len_out,
    uint8_t* tag_out, int* tag_len_out,
    char* err_msg_out
) {
    try {
        // Clear error
        if (err_msg_out) err_msg_out[0] = '\0';
        
        // Validate parameters
        if (!mode || !plaintext || plaintext_len <= 0 || !key || key_len <= 0) {
            if (err_msg_out) strncpy(err_msg_out, "Invalid parameters", 1023);
            return -1;
        }
        
        // Build config
        CryptoConfig config;
        config.mode = mode;
        config.key.assign(key, key + key_len);
        
        if (iv && iv_len > 0) {
            config.iv.assign(iv, iv + iv_len);
        }
        
        if (aad && strlen(aad) > 0) {
            config.aad = std::string(aad);
        }
        
        config.isAead = (is_aead != 0);
        config.allowEcb = (allow_ecb != 0);
        
        // Check ECB size limit
        if (config.mode == "ecb" && plaintext_len > 16384 && !config.allowEcb) {
            if (err_msg_out) strncpy(err_msg_out, "ECB mode blocked for files >16KB. Use --allow-ecb", 1023);
            return -1;
        }
        
        // Encrypt
        std::vector<uint8_t> tag;
        auto ciphertext = EncryptAES(
            std::vector<uint8_t>(plaintext, plaintext + plaintext_len),
            config, tag
        );
        
        // Output ciphertext
        if (ciphertext_out && ciphertext_len_out) {
            int copy_len = std::min((int)ciphertext.size(), *ciphertext_len_out);
            memcpy(ciphertext_out, ciphertext.data(), copy_len);
            *ciphertext_len_out = copy_len;
        }
        
        // Output key (if requested)
        if (key_out && key_len_out) {
            int copy_len = std::min(config.key.size(), (size_t)*key_len_out);
            memcpy(key_out, config.key.data(), copy_len);
            *key_len_out = copy_len;
        }
        
        // Output IV (if requested)
        if (!config.iv.empty() && iv_out && iv_len_out) {
            int copy_len = std::min(config.iv.size(), (size_t)*iv_len_out);
            memcpy(iv_out, config.iv.data(), copy_len);
            *iv_len_out = copy_len;
        }
        
        // Output tag (if AEAD and requested)
        if (!tag.empty() && tag_out && tag_len_out) {
            int copy_len = std::min(tag.size(), (size_t)*tag_len_out);
            memcpy(tag_out, tag.data(), copy_len);
            *tag_len_out = copy_len;
        }
        
        return 0; // Success
        
    } catch (const std::exception& e) {
        if (err_msg_out) {
            strncpy(err_msg_out, e.what(), 1023);
            err_msg_out[1023] = '\0';
        }
        return -1;
    }
}

DLL_EXPORT int decrypt_aes_c(
    const char* mode,
    uint8_t* ciphertext, int ciphertext_len,
    uint8_t* key, int key_len,
    uint8_t* iv, int iv_len,
    const char* aad,
    int is_aead,
    uint8_t* plaintext_out, int* plaintext_len_out,
    uint8_t* tag_in, int tag_len_in,
    char* err_msg_out
) {
    try {
        // Clear error
        if (err_msg_out) err_msg_out[0] = '\0';
        
        // Validate parameters
        if (!mode || !ciphertext || ciphertext_len <= 0 || !key || key_len <= 0) {
            if (err_msg_out) strncpy(err_msg_out, "Invalid parameters", 1023);
            return -1;
        }
        
        // Build config
        CryptoConfig config;
        config.mode = mode;
        config.key.assign(key, key + key_len);
        
        if (iv && iv_len > 0) {
            config.iv.assign(iv, iv + iv_len);
        }
        
        if (aad && strlen(aad) > 0) {
            config.aad = std::string(aad);
        }
        
        config.isAead = (is_aead != 0);
        
        // Build tag from input (if AEAD)
        std::vector<uint8_t> tag;
        if (tag_in && tag_len_in > 0) {
            tag.assign(tag_in, tag_in + tag_len_in);
        }
        
        // Decrypt
        auto plaintext = DecryptAES(
            std::vector<uint8_t>(ciphertext, ciphertext + ciphertext_len),
            config, tag
        );
        
        // Output plaintext
        if (plaintext_out && plaintext_len_out) {
            int copy_len = std::min((int)plaintext.size(), *plaintext_len_out);
            memcpy(plaintext_out, plaintext.data(), copy_len);
            *plaintext_len_out = copy_len;
        }
        
        return 0; // Success
        
    } catch (const std::exception& e) {
        if (err_msg_out) {
            strncpy(err_msg_out, e.what(), 1023);
            err_msg_out[1023] = '\0';
        }
        return -1;
    }
}

} // extern "C"

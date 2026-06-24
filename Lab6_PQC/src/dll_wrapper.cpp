// dll_wrapper.cpp - DLL exports for Lab 6
#include "dll_export.hpp"
#include "pq_engine.hpp"
#include "utils.hpp"
#include <cstring>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>

using namespace lab6;

static thread_local char g_error_msg[1024];
static thread_local std::string g_result_buffer;

extern "C" {

DLL_EXPORT int lab6_keygen(const char* algo, const char* pub_file, const char* priv_file, char* error_msg) {
    try {
        g_error_msg[0] = '\0';
        auto a = pq_engine::parse_algo(algo);
        pq_engine::generate_keypair(a, pub_file, priv_file);
        return 0;
    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return -1;
    }
}

DLL_EXPORT const char* lab6_sign(const char* algo, const char* hash_algo, const char* priv_key_file,
    const char* message, int msg_len, const char* output_file, int encode_mode, char* error_msg) {
    try {
        auto a = pq_engine::parse_algo(algo);
        auto h = pq_engine::parse_hash(hash_algo);
        if (!utils::file_exists(priv_key_file)) { strncpy_s(error_msg, 1024, "Key file not found", 1023); return nullptr; }
        void* key = pq_engine::load_private_key(priv_key_file, a);
        std::vector<uint8_t> msg(message, message + msg_len);
        auto sig = pq_engine::sign(key, a, h, msg);
        pq_engine::free_key(key);
        if (output_file && strlen(output_file) > 0) utils::write_file(output_file, sig);
        g_result_buffer = utils::encode_output(sig, static_cast<lab6::utils::EncodeMode>(encode_mode));
        return g_result_buffer.c_str();
    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT int lab6_verify(const char* algo, const char* hash_algo, const char* pub_key_file,
    const char* message, int msg_len, const char* sig_file, char* error_msg) {
    try {
        auto a = pq_engine::parse_algo(algo);
        auto h = pq_engine::parse_hash(hash_algo);
        void* key = pq_engine::load_public_key(pub_key_file, a);
        std::vector<uint8_t> msg(message, message + msg_len);
        auto sig = utils::read_file(sig_file);
        bool valid = pq_engine::verify(key, a, h, msg, sig);
        pq_engine::free_key(key);
        return valid ? 1 : 0;
    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return -1;
    }
}

DLL_EXPORT const char* lab6_encaps(const char* algo, const char* pub_key_file,
    const char* ct_file, const char* ss_file, char* error_msg) {
    try {
        auto a = pq_engine::parse_algo(algo);
        void* key = pq_engine::load_public_key(pub_key_file, a);
        auto [ct, ss] = pq_engine::encapsulate(key, a);
        pq_engine::free_key(key);
        if (ct_file && strlen(ct_file) > 0) utils::write_file(ct_file, ct);
        if (ss_file && strlen(ss_file) > 0) utils::write_file(ss_file, ss);
        g_result_buffer = "OK: ct=" + utils::to_hex(ct) + " ss=" + utils::to_hex(ss);
        return g_result_buffer.c_str();
    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return nullptr;
    }
}

DLL_EXPORT int lab6_decaps(const char* algo, const char* priv_key_file,
    const char* ct_file, const char* ss_file, char* error_msg) {
    try {
        auto a = pq_engine::parse_algo(algo);
        void* key = pq_engine::load_private_key(priv_key_file, a);
        auto ct = utils::read_file(ct_file);
        auto ss = pq_engine::decapsulate(key, a, ct);
        pq_engine::free_key(key);
        if (ss_file && strlen(ss_file) > 0) utils::write_file(ss_file, ss);
        return 0;
    } catch (const std::exception& e) {
        strncpy_s(error_msg, 1024, e.what(), 1023);
        error_msg[1023] = '\0';
        return -1;
    }
}

DLL_EXPORT const char* lab6_run_benchmark(const char*, char* error_msg) {
    try {
        g_result_buffer = "=== Post-Quantum Benchmark (Lab 6) ===\nFull benchmark requires CLI: benchmark";
        return g_result_buffer.c_str();
    } catch (...) { strncpy_s(error_msg, 1024, "error", 1023); return nullptr; }
}

DLL_EXPORT const char* lab6_run_tests(int* total, int* passed, int* failed, char* error_msg) {
    try {
        std::ostringstream oss;
        oss << "=== PQ Basic Validation Tests (Lab 6) ===" << std::endl;
        *total = *passed = *failed = 0;

        auto test = [&](const std::string& label, auto fn) {
            try { fn(); oss << "[PASS] " << label << std::endl; (*passed)++; }
            catch (...) { oss << "[FAIL] " << label << std::endl; (*failed)++; }
            (*total)++;
        };

        test("ML-DSA-44 keygen", []{
            std::string p = "dll_test_pub.pem", r = "dll_test_priv.pem";
            pq_engine::generate_keypair(pq_engine::PQAlgo::ML_DSA_44, p, r);
            void* k = pq_engine::load_public_key(p, pq_engine::PQAlgo::ML_DSA_44);
            bool ok = (k != nullptr);
            pq_engine::free_key(k); std::remove(p.c_str()); std::remove(r.c_str());
            if (!ok) throw std::runtime_error("key load failed");
        });

        test("ML-DSA-44 sign/verify", []{
            std::string p = "dll_s_pub.pem", r = "dll_s_priv.pem";
            pq_engine::generate_keypair(pq_engine::PQAlgo::ML_DSA_44, p, r);
            void* pk = pq_engine::load_private_key(r, pq_engine::PQAlgo::ML_DSA_44);
            void* pub = pq_engine::load_public_key(p, pq_engine::PQAlgo::ML_DSA_44);
            auto mb = utils::string_to_bytes("test");
            auto sig = pq_engine::sign(pk, pq_engine::PQAlgo::ML_DSA_44, pq_engine::HashAlgo::SHA256, mb);
            bool ok = pq_engine::verify(pub, pq_engine::PQAlgo::ML_DSA_44, pq_engine::HashAlgo::SHA256, mb, sig);
            pq_engine::free_key(pk); pq_engine::free_key(pub);
            std::remove(p.c_str()); std::remove(r.c_str());
            if (!ok) throw std::runtime_error("verify failed");
        });

        test("ML-KEM-512 encaps/decaps", []{
            std::string p = "dll_k_pub.pem", r = "dll_k_priv.pem";
            pq_engine::generate_keypair(pq_engine::PQAlgo::ML_KEM_512, p, r);
            void* pk = pq_engine::load_private_key(r, pq_engine::PQAlgo::ML_KEM_512);
            void* pub = pq_engine::load_public_key(p, pq_engine::PQAlgo::ML_KEM_512);
            auto [ct, ss1] = pq_engine::encapsulate(pub, pq_engine::PQAlgo::ML_KEM_512);
            auto ss2 = pq_engine::decapsulate(pk, pq_engine::PQAlgo::ML_KEM_512, ct);
            pq_engine::free_key(pk); pq_engine::free_key(pub);
            std::remove(p.c_str()); std::remove(r.c_str());
            if (ss1 != ss2) throw std::runtime_error("KEM mismatch");
        });

        *total = *passed + *failed;
        oss << std::endl << "Results: " << *passed << "/" << *total << " passed" << std::endl;
        g_result_buffer = oss.str();
        return g_result_buffer.c_str();
    } catch (...) { strncpy_s(error_msg, 1024, "error", 1023); return nullptr; }
}

DLL_EXPORT const char* lab6_run_kat(const char* vectors_file, char* error_msg) {
    try {
        std::ostringstream oss;
        oss << "=== PQ KAT Validation (Lab 6) ===" << std::endl;
        oss << "Vectors file: " << vectors_file << std::endl;
        std::ifstream check(vectors_file);
        if (!check.good()) oss << "[ERROR] File not found" << std::endl;
        else oss << "[INFO] Full KAT validation requires CLI: pqtool --kat " << vectors_file << std::endl;
        g_result_buffer = oss.str();
        return g_result_buffer.c_str();
    } catch (...) { strncpy_s(error_msg, 1024, "error", 1023); return nullptr; }
}

DLL_EXPORT void lab6_free_string(const char*) {}

} // extern "C"

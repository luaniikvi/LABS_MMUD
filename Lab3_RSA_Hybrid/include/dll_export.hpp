// dll_export.hpp - DLL export macros for Lab 3
#pragma once

#ifdef _WIN32
    #ifdef BUILDING_DLL
        #define DLL_EXPORT __declspec(dllexport)
    #else
        #define DLL_EXPORT __declspec(dllimport)
    #endif
#else
    #define DLL_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Simple C-style API for Python ctypes

// Key Generation
DLL_EXPORT int lab3_keygen(
    int bits,
    const char* pub_file,
    const char* priv_file,
    char* error_msg
);

// Encryption/Decryption
DLL_EXPORT const char* lab3_encrypt(
    const char* pub_key_file,
    const char* plaintext,
    const char* label,
    const char* aad_hex,
    const char* output_file,
    char* error_msg
);

DLL_EXPORT int lab3_decrypt(
    const char* priv_key_file,
    const char* input_file,
    const char* label,
    const char* output_file,
    char* error_msg
);

// Benchmark
DLL_EXPORT const char* lab3_run_benchmark(
    const char* mode_filter,
    char* error_msg
);

// Unit Tests
DLL_EXPORT const char* lab3_run_tests(
    int* total,
    int* passed,
    int* failed,
    char* error_msg
);

// KAT Validation
DLL_EXPORT const char* lab3_run_kat(
    const char* vectors_file,
    char* error_msg
);

DLL_EXPORT void lab3_free_string(const char* str);

#ifdef __cplusplus
}
#endif

// dll_export.hpp - DLL export macros for Lab 1
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

// Encryption/Decryption
DLL_EXPORT const char* lab1_encrypt(
    const char* mode,
    const char* key_hex,
    const char* iv_hex,
    const char* plaintext,
    const char* aad_hex,
    int* out_length,
    char* error_msg
);

DLL_EXPORT const char* lab1_decrypt(
    const char* mode,
    const char* key_hex,
    const char* iv_hex,
    const char* ciphertext_hex,
    const char* tag_hex,
    const char* aad_hex,
    int* out_length,
    char* error_msg
);

// Benchmark - runs and returns output as string
DLL_EXPORT const char* lab1_run_benchmark(
    const char* mode_filter,  // "all" or specific mode
    int size_filter,          // 0 for all, or size in bytes
    char* error_msg
);

// Unit Tests - runs and returns output as string
DLL_EXPORT const char* lab1_run_tests(
    int* total,
    int* passed,
    int* failed,
    char* error_msg
);

// KAT Validation - runs and returns output as string
DLL_EXPORT const char* lab1_run_kat(
    const char* vectors_file,
    char* error_msg
);

DLL_EXPORT void lab1_free_string(const char* str);

#ifdef __cplusplus
}
#endif

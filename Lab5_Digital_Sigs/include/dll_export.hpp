// dll_export.hpp - DLL export macros for Lab 5
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

// Key generation
DLL_EXPORT int lab5_keygen(
    const char* algo,
    const char* pub_file,
    const char* priv_file,
    char* error_msg
);

// Sign
DLL_EXPORT const char* lab5_sign(
    const char* algo,
    const char* hash_algo,
    const char* priv_key_file,
    const char* message,
    int msg_len,
    const char* output_file,
    int encode_mode,
    char* error_msg
);

// Verify
DLL_EXPORT int lab5_verify(
    const char* algo,
    const char* hash_algo,
    const char* pub_key_file,
    const char* message,
    int msg_len,
    const char* sig_file,
    char* error_msg
);

// Sign file
DLL_EXPORT const char* lab5_sign_file(
    const char* algo,
    const char* hash_algo,
    const char* priv_key_file,
    const char* input_file,
    const char* output_file,
    int encode_mode,
    char* error_msg
);

// Verify file
DLL_EXPORT int lab5_verify_file(
    const char* algo,
    const char* hash_algo,
    const char* pub_key_file,
    const char* input_file,
    const char* sig_file,
    char* error_msg
);

// Benchmark
DLL_EXPORT const char* lab5_run_benchmark(
    const char* mode_filter,
    char* error_msg
);

// Unit Tests
DLL_EXPORT const char* lab5_run_tests(
    int* total,
    int* passed,
    int* failed,
    char* error_msg
);

// KAT Validation
DLL_EXPORT const char* lab5_run_kat(
    const char* vectors_file,
    char* error_msg
);

DLL_EXPORT void lab5_free_string(const char* str);

#ifdef __cplusplus
}
#endif

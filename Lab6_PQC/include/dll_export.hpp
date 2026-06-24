// dll_export.hpp - DLL export macros for Lab 6
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
DLL_EXPORT int lab6_keygen(
    const char* algo,
    const char* pub_file,
    const char* priv_file,
    char* error_msg
);

// Sign (ML-DSA)
DLL_EXPORT const char* lab6_sign(
    const char* algo,
    const char* hash_algo,
    const char* priv_key_file,
    const char* message,
    int msg_len,
    const char* output_file,
    int encode_mode,
    char* error_msg
);

// Verify (ML-DSA)
DLL_EXPORT int lab6_verify(
    const char* algo,
    const char* hash_algo,
    const char* pub_key_file,
    const char* message,
    int msg_len,
    const char* sig_file,
    char* error_msg
);

// Sign file (ML-DSA)
DLL_EXPORT const char* lab6_sign_file(
    const char* algo,
    const char* hash_algo,
    const char* priv_key_file,
    const char* input_file,
    const char* output_file,
    int encode_mode,
    char* error_msg
);

// Verify file (ML-DSA)
DLL_EXPORT int lab6_verify_file(
    const char* algo,
    const char* hash_algo,
    const char* pub_key_file,
    const char* input_file,
    const char* sig_file,
    char* error_msg
);

// KEM encapsulate (ML-KEM)
DLL_EXPORT const char* lab6_encaps(
    const char* algo,
    const char* pub_key_file,
    const char* ct_file,
    const char* ss_file,
    char* error_msg
);

// KEM decapsulate (ML-KEM)
DLL_EXPORT int lab6_decaps(
    const char* algo,
    const char* priv_key_file,
    const char* ct_file,
    const char* ss_file,
    char* error_msg
);

// PQ Certificate operations
DLL_EXPORT const char* lab6_cert_sign(
    const char* ca_priv_file,
    const char* subject_pub_file,
    const char* subject_name,
    const char* output_file,
    char* error_msg
);

DLL_EXPORT int lab6_cert_verify(
    const char* ca_pub_file,
    const char* cert_file,
    char* error_msg
);

// Benchmark
DLL_EXPORT const char* lab6_run_benchmark(
    const char* mode_filter,
    char* error_msg
);

// Unit Tests
DLL_EXPORT const char* lab6_run_tests(
    int* total,
    int* passed,
    int* failed,
    char* error_msg
);

// KAT Validation
DLL_EXPORT const char* lab6_run_kat(
    const char* vectors_file,
    char* error_msg
);

DLL_EXPORT void lab6_free_string(const char* str);

#ifdef __cplusplus
}
#endif

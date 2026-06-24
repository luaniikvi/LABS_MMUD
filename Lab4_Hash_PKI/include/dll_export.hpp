// dll_export.hpp - DLL export macros for Lab 4
#pragma once
#include <cstdint>

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

// Hashing
DLL_EXPORT int lab4_hash(
    const char* algo,
    const uint8_t* data,
    int data_len,
    char* out_hex,
    int out_hex_len,
    char* err_buf,
    int err_buf_len
);

DLL_EXPORT int lab4_hash_file(
    const char* algo,
    const char* filepath,
    int stream_mode,
    char* out_hex,
    int out_hex_len,
    char* err_buf,
    int err_buf_len
);

// SHAKE (extendable-output)
DLL_EXPORT int lab4_shake(
    const char* algo,
    const uint8_t* data,
    int data_len,
    int outlen,
    char* out_hex,
    int out_hex_len,
    char* err_buf,
    int err_buf_len
);

DLL_EXPORT int lab4_shake_file(
    const char* algo,
    const char* filepath,
    int stream_mode,
    int outlen,
    char* out_hex,
    int out_hex_len,
    char* err_buf,
    int err_buf_len
);

// HMAC
DLL_EXPORT int lab4_hmac(
    const char* algo,
    const uint8_t* key,
    int key_len,
    const uint8_t* data,
    int data_len,
    char* out_hex,
    int out_hex_len,
    char* err_buf,
    int err_buf_len
);

DLL_EXPORT int lab4_hmac_file(
    const char* algo,
    const uint8_t* key,
    int key_len,
    const char* filepath,
    int stream_mode,
    char* out_hex,
    int out_hex_len,
    char* err_buf,
    int err_buf_len
);

// X.509
DLL_EXPORT int lab4_parse_x509(
    const char* cert_path,
    char* out_json,
    int out_json_len,
    char* err_buf,
    int err_buf_len
);

DLL_EXPORT int lab4_verify_x509(
    const char* cert_path,
    const char* issuer_pub_path,
    char* err_buf,
    int err_buf_len
);

// Length-extension attack demo
DLL_EXPORT int lab4_length_ext(
    const char* mac_hex,
    int key_len,
    int msg_len,
    const char* append_data,
    char* out_json,
    int out_json_len,
    char* err_buf,
    int err_buf_len
);

// MD5 collision demo
DLL_EXPORT int lab4_md5_demo(
    const char* dir_path,
    char* out_json,
    int out_json_len,
    char* err_buf,
    int err_buf_len
);

// KAT runner
DLL_EXPORT const char* lab4_run_kat(
    const char* vectors_file,
    char* err_buf,
    int err_buf_len
);

// Helper
DLL_EXPORT void lab4_free_string(const char* s);

#ifdef __cplusplus
}
#endif

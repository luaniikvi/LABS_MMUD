#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

// Crypto++ for SHA-256/SHA-384 hashing
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

namespace lab5 {
namespace utils {

std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() % 2 != 0) {
        fail_closed("Invalid hex string: odd length");
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string to_base64(const std::vector<uint8_t>& data) {
    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (auto byte : data) {
        char_array_3[i++] = byte;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }

    return ret;
}

std::vector<uint8_t> from_base64(const std::string& base64) {
    std::vector<uint8_t> ret;
    int i = 0;
    unsigned char char_array_4[4], char_array_3[3];

    for (char c : base64) {
        if (c == '=') break;
        auto pos = base64_chars.find(c);
        if (pos == std::string::npos) continue;
        
        char_array_4[i++] = static_cast<unsigned char>(pos);
        if (i == 4) {
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 4; j++)
            char_array_4[j] = 0;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }

    return ret;
}

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        fail_closed("Cannot open file: " + path);
    }
    
    std::vector<uint8_t> buffer(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    
    return buffer;
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        fail_closed("Cannot write to file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::string read_text_file(const std::string& path) {
    auto bytes = read_file(path);
    return std::string(bytes.begin(), bytes.end());
}

void write_text_file(const std::string& path, const std::string& text) {
    std::ofstream file(path);
    if (!file.is_open()) {
        fail_closed("Cannot write to file: " + path);
    }
    file << text;
}

std::vector<uint8_t> string_to_bytes(const std::string& str) {
#ifdef _WIN32
    if (str.empty()) return {};
    
    int wide_len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (wide_len == 0) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    std::wstring wide_str(wide_len, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wide_str[0], wide_len);
    
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8_len == 0) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    std::string utf8_str(utf8_len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), -1, &utf8_str[0], utf8_len, nullptr, nullptr);
    
    if (!utf8_str.empty()) utf8_str.pop_back();
    
    return std::vector<uint8_t>(utf8_str.begin(), utf8_str.end());
#else
    return std::vector<uint8_t>(str.begin(), str.end());
#endif
}

std::string bytes_to_string(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return "";
    
    std::string utf8_str(bytes.begin(), bytes.end());
    
#ifdef _WIN32
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, nullptr, 0);
    if (wide_len == 0) {
        return std::string(bytes.begin(), bytes.end());
    }
    
    std::wstring wide_str(wide_len, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, &wide_str[0], wide_len);
    
    int ansi_len = WideCharToMultiByte(CP_ACP, 0, wide_str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (ansi_len == 0) {
        return std::string(bytes.begin(), bytes.end());
    }
    
    std::string ansi_str(ansi_len, 0);
    WideCharToMultiByte(CP_ACP, 0, wide_str.c_str(), -1, &ansi_str[0], ansi_len, nullptr, nullptr);
    
    if (!ansi_str.empty()) ansi_str.pop_back();
    
    return ansi_str;
#else
    return std::string(bytes.begin(), bytes.end());
#endif
}

void fail_closed(const std::string& message) {
    std::cerr << "[ERROR] " << message << std::endl;
    throw std::runtime_error(message);
}

bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    CryptoPP::SHA256 hash;
    std::vector<uint8_t> digest(CryptoPP::SHA256::DIGESTSIZE);
    hash.CalculateDigest(digest.data(), data.data(), data.size());
    return digest;
}

std::vector<uint8_t> sha384(const std::vector<uint8_t>& data) {
    CryptoPP::SHA384 hash;
    std::vector<uint8_t> digest(CryptoPP::SHA384::DIGESTSIZE);
    hash.CalculateDigest(digest.data(), data.data(), data.size());
    return digest;
}

utils::EncodeMode parse_encode_mode(const std::string& mode_str) {
    if (mode_str == "hex") return ENCODE_HEX;
    if (mode_str == "base64") return ENCODE_BASE64;
    if (mode_str == "raw") return ENCODE_RAW;
    fail_closed("Invalid encode mode: " + mode_str + " (use hex, base64, or raw)");
    return ENCODE_RAW;
}

std::string encode_output(const std::vector<uint8_t>& data, EncodeMode mode) {
    switch (mode) {
        case ENCODE_HEX: return to_hex(data);
        case ENCODE_BASE64: return to_base64(data);
        default: return std::string(data.begin(), data.end());
    }
}

std::vector<uint8_t> decode_input(const std::string& data_str, EncodeMode mode) {
    switch (mode) {
        case ENCODE_HEX: return from_hex(data_str);
        case ENCODE_BASE64: return from_base64(data_str);
        default: return std::vector<uint8_t>(data_str.begin(), data_str.end());
    }
}

} // namespace utils
} // namespace lab5

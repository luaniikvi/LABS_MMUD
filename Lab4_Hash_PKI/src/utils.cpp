#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace lab4 {
namespace utils {

// ============================================================================
// Hex encoding/decoding (hand-rolled)
// ============================================================================

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string to_hex(const std::vector<uint8_t>& data) {
    return to_hex(data.data(), data.size());
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean += c;
        }
    }
    if (clean.size() % 2 != 0) {
        fail_closed("Invalid hex string: odd length");
    }
    std::vector<uint8_t> result;
    result.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2) {
        std::string byte_str = clean.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            result.push_back(byte);
        } catch (...) {
            fail_closed("Invalid hex character in: " + byte_str);
        }
    }
    return result;
}

// ============================================================================
// Base64 encoding/decoding (hand-rolled)
// ============================================================================

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string to_base64(const std::vector<uint8_t>& data) {
    std::string result;
    size_t i = 0;
    size_t len = data.size();
    result.reserve(((len + 2) / 3) * 4);

    while (i < len) {
        uint32_t a = (i < len) ? data[i++] : 0;
        uint32_t b = (i < len) ? data[i++] : 0;
        uint32_t c = (i < len) ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        size_t remaining = len - (i - 3);
        result += b64_table[(triple >> 18) & 0x3F];
        result += b64_table[(triple >> 12) & 0x3F];
        result += (remaining > 1) ? b64_table[(triple >> 6) & 0x3F] : '=';
        result += (remaining > 2) ? b64_table[triple & 0x3F] : '=';
    }
    return result;
}

std::vector<uint8_t> from_base64(const std::string& b64) {
    static const int decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    std::vector<uint8_t> result;
    result.reserve((b64.size() / 4) * 3);

    for (size_t i = 0; i < b64.size(); i += 4) {
        if (i + 4 > b64.size()) break;

        int a = decode_table[static_cast<unsigned char>(b64[i])];
        int b = decode_table[static_cast<unsigned char>(b64[i + 1])];
        int c = (b64[i + 2] != '=') ? decode_table[static_cast<unsigned char>(b64[i + 2])] : 0;
        int d = (b64[i + 3] != '=') ? decode_table[static_cast<unsigned char>(b64[i + 3])] : 0;

        if (a < 0 || b < 0) {
            fail_closed("Invalid base64 character");
        }

        uint32_t triple = (a << 18) | (b << 12) | (c << 6) | d;
        result.push_back((triple >> 16) & 0xFF);
        if (b64[i + 2] != '=') result.push_back((triple >> 8) & 0xFF);
        if (b64[i + 3] != '=') result.push_back(triple & 0xFF);
    }
    return result;
}

// ============================================================================
// File I/O (binary-safe)
// ============================================================================

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        fail_closed("Cannot open file: " + path);
    }
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(data.data()), size);
    }
    return data;
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        fail_closed("Cannot create file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::string read_text_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        fail_closed("Cannot open file: " + path);
    }
    return std::string((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
}

void write_text_file(const std::string& path, const std::string& text) {
    std::ofstream file(path);
    if (!file.is_open()) {
        fail_closed("Cannot create file: " + path);
    }
    file << text;
}

// ============================================================================
// Utilities
// ============================================================================

bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

uint64_t file_size(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        fail_closed("Cannot open file: " + path);
    }
    return static_cast<uint64_t>(file.tellg());
}

void fail_closed(const std::string& message) {
    std::cerr << "[ERROR] " << message << std::endl;
    throw std::runtime_error(message);
}

// ============================================================================
// Byte conversion (Windows UTF-8)
// ============================================================================

std::vector<uint8_t> string_to_bytes(const std::string& s) {
#ifdef _WIN32
    // Convert UTF-8 to wide string, then back to UTF-8 bytes
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (wlen <= 0) {
        return std::vector<uint8_t>(s.begin(), s.end());
    }
    std::vector<wchar_t> wstr(wlen);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, wstr.data(), wlen);

    int blen = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), -1, nullptr, 0, nullptr, nullptr);
    if (blen <= 0) {
        return std::vector<uint8_t>(s.begin(), s.end());
    }
    std::vector<uint8_t> result(blen - 1); // exclude null terminator
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), -1, reinterpret_cast<char*>(result.data()), blen, nullptr, nullptr);
    return result;
#else
    return std::vector<uint8_t>(s.begin(), s.end());
#endif
}

std::string bytes_to_string(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

} // namespace utils
} // namespace lab4

#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <nlohmann/json.hpp>
#include "rsa_engine.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

using json = nlohmann::json;

namespace lab3 {
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
    int in_ = 0;
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
    // On Windows, convert from system locale to UTF-8, then to bytes
    // On Linux/Mac, the string is already UTF-8
#ifdef _WIN32
    if (str.empty()) return {};
    
    // Convert from system locale to wide string
    int wide_len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (wide_len == 0) {
        // Fallback: treat as raw bytes
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    std::wstring wide_str(wide_len, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wide_str[0], wide_len);
    
    // Convert wide string to UTF-8
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8_len == 0) {
        // Fallback: treat as raw bytes
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    std::string utf8_str(utf8_len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), -1, &utf8_str[0], utf8_len, nullptr, nullptr);
    
    // Remove null terminator
    if (!utf8_str.empty()) utf8_str.pop_back();
    
    return std::vector<uint8_t>(utf8_str.begin(), utf8_str.end());
#else
    // Linux/Mac: string is already UTF-8
    return std::vector<uint8_t>(str.begin(), str.end());
#endif
}

std::string bytes_to_string(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return "";
    
    std::string utf8_str(bytes.begin(), bytes.end());
    
#ifdef _WIN32
    // Convert UTF-8 to wide string
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, nullptr, 0);
    if (wide_len == 0) {
        // Fallback: treat as raw bytes
        return std::string(bytes.begin(), bytes.end());
    }
    
    std::wstring wide_str(wide_len, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, &wide_str[0], wide_len);
    
    // Convert wide string to system locale
    int ansi_len = WideCharToMultiByte(CP_ACP, 0, wide_str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (ansi_len == 0) {
        // Fallback: treat as raw bytes
        return std::string(bytes.begin(), bytes.end());
    }
    
    std::string ansi_str(ansi_len, 0);
    WideCharToMultiByte(CP_ACP, 0, wide_str.c_str(), -1, &ansi_str[0], ansi_len, nullptr, nullptr);
    
    // Remove null terminator
    if (!ansi_str.empty()) ansi_str.pop_back();
    
    return ansi_str;
#else
    // Linux/Mac: string is already UTF-8
    return std::string(bytes.begin(), bytes.end());
#endif
}

void fail_closed(const std::string& message) {
    std::cerr << "[ERROR] " << message << std::endl;
    throw std::runtime_error(message);
}

} // namespace utils
} // namespace lab3

void RunKatTests(const std::string& katFilePath) {
    using namespace lab3;
    
    // Read JSON file
    std::string json_str = utils::read_text_file(katFilePath);
    json kats = json::parse(json_str);
    
    std::string description = kats.value("description", "Unknown");
    std::string algorithm = kats.value("algorithm", "Unknown");
    
    std::cout << "\nAlgorithm: " << algorithm << std::endl;
    std::cout << "Description: " << description << std::endl;
    std::cout << "\nRunning tests...\n" << std::endl;
    
    int passed = 0;
    int failed = 0;
    int total = 0;
    
    // Generate temporary key pair for testing
    std::string pub_file = "kat_test_pub.pem";
    std::string priv_file = "kat_test_priv.pem";
    std::string meta_file = "kat_test_meta.json";
    
    try {
        rsa_engine::generate_keypair(3072, pub_file, priv_file, meta_file);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to generate test keys: " << e.what() << std::endl;
        return;
    }
    
    auto pub_key = rsa_engine::load_public_key_pem(pub_file);
    auto priv_key = rsa_engine::load_private_key_pem(priv_file);
    
    for (const auto& test : kats["tests"]) {
        total++;
        int id = test.value("id", total);
        std::string desc = test.value("description", "Test " + std::to_string(id));
        std::string expected = test.value("expected_result", "success");
        
        std::vector<uint8_t> plaintext;
        std::string label = test.value("label", "");
        
        // Get plaintext from test vector
        if (test.contains("plaintext")) {
            plaintext = utils::string_to_bytes(test["plaintext"]);
        } else if (test.contains("plaintext_hex")) {
            plaintext = utils::from_hex(test["plaintext_hex"]);
        } else if (test.contains("plaintext_size")) {
            plaintext = std::vector<uint8_t>(test["plaintext_size"], 0x42);
        } else {
            std::cout << "[SKIP] Test " << id << ": " << desc << " (no plaintext)" << std::endl;
            continue;
        }
        
        try {
            // Encrypt
            auto ciphertext = rsa_engine::encrypt(pub_key, plaintext, label);
            
            // Decrypt
            auto decrypted = rsa_engine::decrypt(priv_key, ciphertext, label);
            
            // Verify
            if (decrypted == plaintext) {
                std::cout << "[PASS] Test " << id << ": " << desc << std::endl;
                passed++;
            } else {
                std::cout << "[FAIL] Test " << id << ": " << desc << " (decrypted mismatch)" << std::endl;
                failed++;
            }
        } catch (const std::exception& e) {
            if (expected == "fail") {
                std::cout << "[PASS] Test " << id << ": " << desc << " (expected failure)" << std::endl;
                passed++;
            } else {
                std::cout << "[FAIL] Test " << id << ": " << desc << " (" << e.what() << ")" << std::endl;
                failed++;
            }
        }
    }
    
    // Clean up test keys
    try {
        std::remove(pub_file.c_str());
        std::remove(priv_file.c_str());
        std::remove(meta_file.c_str());
    } catch (...) {}
    
    // Print summary
    std::cout << "\n======================================================================" << std::endl;
    std::cout << "KAT Summary" << std::endl;
    std::cout << "======================================================================" << std::endl;
    std::cout << "Total tests: " << total << std::endl;
    std::cout << "Passed:      " << passed << std::endl;
    std::cout << "Failed:      " << failed << std::endl;
    std::cout << "Success rate: " << (total > 0 ? (passed * 100.0 / total) : 0) << "%" << std::endl;
    std::cout << "======================================================================" << std::endl;
    
    if (failed > 0) {
        std::cerr << "\n[WARNING] " << failed << " test(s) failed!" << std::endl;
    }
}

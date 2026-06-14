// utils.cpp
#include "utils.hpp"
#include "crypto_engine.hpp"
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <fstream>
#include <sstream>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <stdexcept>

static bool IsHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static bool IsAllHex(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!IsHexChar(c)) return false;
    }
    return s.size() % 2 == 0;
}

static bool IsLikelyKeyHexLength(size_t hexLen) {
    return hexLen == 32 || hexLen == 48 || hexLen == 64 || hexLen == 128;
}

static bool IsLikelyIvHexLength(size_t hexLen) {
    return hexLen == 24 || hexLen == 32 || (hexLen >= 14 && hexLen <= 26);
}

std::string ToHex(const std::vector<uint8_t>& bytes) {
    static const char hexDigits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(hexDigits[(b >> 4) & 0x0F]);
        out.push_back(hexDigits[b & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> FromHex(const std::string& hexStr) {
    std::string filtered = hexStr;
    filtered.erase(std::remove_if(filtered.begin(), filtered.end(), ::isspace), filtered.end());

    for (char c : filtered) {
        if (!IsHexChar(c)) {
            throw std::runtime_error("Malformed input: invalid characters in hexadecimal representation.");
        }
    }
    if (filtered.length() % 2 != 0) {
        throw std::runtime_error("Malformed input: hexadecimal representation has odd length.");
    }

    std::vector<uint8_t> out;
    CryptoPP::StringSource(filtered, true, new CryptoPP::HexDecoder(new CryptoPP::VectorSink(out)));
    return out;
}

std::string ToBase64(const std::vector<uint8_t>& bytes) {
    std::string out;
    CryptoPP::VectorSource(bytes, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(out), false));
    return out;
}

std::vector<uint8_t> ReadBinaryOrHexFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("I/O Error: Failed to open file: " + path);
    }

    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (raw.empty()) {
        throw std::runtime_error("I/O Error: File is empty: " + path);
    }

    const bool isTextFile = std::all_of(raw.begin(), raw.end(), [](uint8_t b) {
        return b == '\n' || b == '\r' || b == '\t' || b == ' '
            || (b >= 32 && b <= 126);
    });

    if (!isTextFile) {
        return raw;
    }

    std::string content(raw.begin(), raw.end());
    bool hasHexHeader = false;
    std::string payload;
    std::istringstream iss(content);
    std::string line;

    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.rfind("#", 0) == 0 || line.rfind("-----", 0) == 0) {
            std::string upper = line;
            std::transform(upper.begin(), upper.end(), upper.begin(),
                [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            if (upper.find("HEX") != std::string::npos) {
                hasHexHeader = true;
            }
            continue;
        }

        if (line.rfind("HEX:", 0) == 0 || line.rfind("hex:", 0) == 0) {
            hasHexHeader = true;
            payload += line.substr(4);
            continue;
        }

        payload += line;
    }

    if (payload.empty()) {
        payload = content;
    }

    std::string filtered = payload;
    filtered.erase(std::remove_if(filtered.begin(), filtered.end(), ::isspace), filtered.end());

    if (IsAllHex(filtered) && (hasHexHeader || IsLikelyKeyHexLength(filtered.size()) || IsLikelyIvHexLength(filtered.size()))) {
        return FromHex(filtered);
    }

    if (hasHexHeader) {
        std::string hexCandidate;
        for (char c : content) {
            if (IsHexChar(c)) {
                hexCandidate += c;
            }
        }
        if (IsAllHex(hexCandidate)) {
            return FromHex(hexCandidate);
        }
    }

    return raw;
}

std::vector<uint8_t> LoadIvOrNonceArg(const std::string& arg) {
    std::ifstream test(arg, std::ios::binary);
    if (test.good()) {
        test.close();
        return ReadBinaryOrHexFile(arg);
    }
    return FromHex(arg);
}

void WriteSidecarJSON(const std::string& filename, const std::string& alg, const std::string& mode,
                      const std::string& ivHex, const std::string& tagHex, const std::string& aadHex) {
    std::ofstream f(filename + ".json");
    if (!f) {
        throw std::runtime_error("I/O Error: Failed to write sidecar JSON: " + filename + ".json");
    }
    f << "{\n"
      << "  \"alg\": \"" << alg << "\",\n"
      << "  \"mode\": \"" << mode << "\",\n"
      << "  \"iv\": \"" << ivHex << "\",\n"
      << "  \"aad\": \"" << aadHex << "\",\n"
      << "  \"tag\": \"" << tagHex << "\"\n"
      << "}\n";
}

using json = nlohmann::json;

void RunKatTest(const std::string& katFilePath) {
    // Clear nonce-reuse registry so KAT vectors can reuse key+nonce pairs
    // (NIST test vectors intentionally reuse keys across multiple test cases)
    ClearNonceRegistry();

    std::ifstream file(katFilePath);
    if (!file) {
        std::cerr << "[KAT ERROR] Cannot open file: " << katFilePath << "\n";
        return;
    }

    json j;
    try {
        file >> j;
    } catch (const json::parse_error& e) {
        std::cerr << "[JSON ERROR] Parse error: " << e.what() << "\n";
        return;
    }

    std::cout << "===================================================\n";
    std::cout << "  STARTING AUTOMATED NIST KAT\n";
    std::cout << "===================================================\n";

    int totalTests = 0, passedTests = 0, failedTests = 0;

    for (const auto& testCase : j["test_cases"]) {
        totalTests++;

        std::string id = testCase.value("id", "UNKNOWN");
        std::string name = testCase.value("name", "Unnamed Test");
        std::string mode = testCase.value("mode", "");
        std::string expected = testCase.value("expected_result", "PASS");
        std::string keyHex = testCase.value("key_hex", "");
        std::string ivHex = testCase.value("iv_hex", "");
        // Support both plaintext_hex (binary) and plaintext (text string)
        std::string plaintextHex = testCase.value("plaintext_hex", "");
        std::string plaintextText = testCase.value("plaintext", "");
        std::string ciphertextHex = testCase.value("ciphertext_hex", "");
        std::string tagHex = testCase.value("tag_hex", "");
        // Support both aad_hex (binary) and aad_text (string)
        std::string aadHex = testCase.value("aad_hex", "");
        std::string aadText = testCase.value("aad_text", "");

        std::cout << "Test [" << id << "] " << name << " -> ";

        CryptoConfig config;
        config.mode = mode;
        config.allowEcb = true;  // allow ECB in KAT

        // Support no_padding flag for NIST-standard test vectors
        if (testCase.contains("no_padding") && testCase["no_padding"].get<bool>()) {
            config.noPadding = true;
        }

        bool caseResult = false;
        try {
            // Key - required
            if (keyHex.empty()) throw std::runtime_error("Missing key_hex");
            config.key = FromHex(keyHex);

            // IV - optional for ECB
            if (!ivHex.empty()) {
                config.iv = FromHex(ivHex);
            }

            // AAD - prefer aad_hex, fall back to aad_text
            if (!aadHex.empty()) {
                std::vector<uint8_t> aadBytes = FromHex(aadHex);
                config.aad.assign(aadBytes.begin(), aadBytes.end());
            } else if (!aadText.empty()) {
                config.aad = aadText;
            }

            if (mode == "gcm" || mode == "ccm") {
                config.isAead = true;
            }

            std::vector<uint8_t> plaintextBytes;
            if (!plaintextHex.empty()) {
                plaintextBytes = FromHex(plaintextHex);
            } else if (!plaintextText.empty()) {
                plaintextBytes.assign(plaintextText.begin(), plaintextText.end());
            }
            std::vector<uint8_t> expectedCipher = ciphertextHex.empty() ? std::vector<uint8_t>{} : FromHex(ciphertextHex);
            std::vector<uint8_t> tagData = tagHex.empty() ? std::vector<uint8_t>{} : FromHex(tagHex);

            if (expected == "PASS") {
                // Encrypt and compare ciphertext (and tag for AEAD)
                std::vector<uint8_t> outTag;
                std::vector<uint8_t> cipher = EncryptAES(plaintextBytes, config, outTag);

                bool cipherMatch = (cipher == expectedCipher);
                bool tagMatch = true;
                if (!tagData.empty()) {
                    tagMatch = (outTag == tagData);
                }
                caseResult = cipherMatch && tagMatch;

                // Also verify roundtrip decrypt
                if (caseResult) {
                    std::vector<uint8_t> dec = DecryptAES(expectedCipher, config, tagData.empty() ? outTag : tagData);
                    caseResult = (dec == plaintextBytes);
                }
            } else {
                // FAIL test: decryption must fail OR produce wrong plaintext
                // Try to decrypt; if it throws, that counts as FAIL (expected)
                bool threw = false;
                bool wrongPlaintext = false;
                try {
                    std::vector<uint8_t> dec = DecryptAES(expectedCipher, config, tagData);
                    wrongPlaintext = (dec != plaintextBytes);
                } catch (...) {
                    threw = true;
                }
                caseResult = threw || wrongPlaintext;
            }
        } catch (...) {
            // Exception during PASS test = failure; exception during FAIL test = expected
            caseResult = (expected == "FAIL");
        }

        if ((expected == "PASS" && caseResult) || (expected == "FAIL" && caseResult)) {
            std::cout << "PASS\n";
            passedTests++;
        } else {
            std::cout << "FAIL\n";
            failedTests++;
        }
    }

    std::cout << "===================================================\n";
    std::cout << "  TOTAL: " << totalTests << " | PASSED: " << passedTests << " | FAILED: " << failedTests << "\n";
    std::cout << "  SUCCESS RATE: " << (totalTests > 0 ? (passedTests * 100 / totalTests) : 0) << "%\n";
    std::cout << "===================================================\n";
}
#include <cryptopp/osrng.h>

std::vector<uint8_t> GenerateRandomBytes(size_t length) {
    CryptoPP::AutoSeededRandomPool rng;
    std::vector<uint8_t> out(length);
    if (length > 0) {
        rng.GenerateBlock(out.data(), out.size());
    }
    return out;
}

std::vector<uint8_t> StringToBytes(const std::string& str) {
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

std::string BytesToString(const std::vector<uint8_t>& bytes) {
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

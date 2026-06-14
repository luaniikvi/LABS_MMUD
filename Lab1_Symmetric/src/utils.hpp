// utils.hpp
#pragma once
#include <string>
#include <vector>
#include <cstdint>

std::string ToHex(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> FromHex(const std::string& hexStr);
std::vector<uint8_t> GenerateRandomBytes(size_t length);
std::string ToBase64(const std::vector<uint8_t>& bytes);

// Read raw binary or hex-encoded content (with optional #/HEX: header) from a file.
std::vector<uint8_t> ReadBinaryOrHexFile(const std::string& path);

// Load IV/nonce from a file path, or decode inline hex when the path does not exist.
std::vector<uint8_t> LoadIvOrNonceArg(const std::string& arg);

void WriteSidecarJSON(const std::string& filename, const std::string& alg, const std::string& mode,
                      const std::string& ivHex, const std::string& tagHex, const std::string& aadHex);

void RunKatTest(const std::string& katFilePath);

// UTF-8 string to bytes conversion
std::vector<uint8_t> StringToBytes(const std::string& str);
std::string BytesToString(const std::vector<uint8_t>& bytes);

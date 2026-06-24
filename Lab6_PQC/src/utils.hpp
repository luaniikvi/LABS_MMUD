#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace lab6 {
namespace utils {

// Hex encoding/decoding
std::string to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> from_hex(const std::string& hex);

// Base64 encoding/decoding
std::string to_base64(const std::vector<uint8_t>& data);
std::vector<uint8_t> from_base64(const std::string& base64);

// File I/O
std::vector<uint8_t> read_file(const std::string& path);
void write_file(const std::string& path, const std::vector<uint8_t>& data);
std::string read_text_file(const std::string& path);
void write_text_file(const std::string& path, const std::string& text);

// String utilities
std::vector<uint8_t> string_to_bytes(const std::string& str);
std::string bytes_to_string(const std::vector<uint8_t>& bytes);

// Error handling
void fail_closed(const std::string& message);

// File existence check
bool file_exists(const std::string& path);

// Compute SHA-256 hash (Crypto++ backend)
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

// Compute SHA-384 hash (Crypto++ backend)
std::vector<uint8_t> sha384(const std::vector<uint8_t>& data);

// Encode modes
enum EncodeMode { ENCODE_RAW = 0, ENCODE_HEX = 1, ENCODE_BASE64 = 2 };
EncodeMode parse_encode_mode(const std::string& mode_str);
std::string encode_output(const std::vector<uint8_t>& data, EncodeMode mode);
std::vector<uint8_t> decode_input(const std::string& data_str, EncodeMode mode);

} // namespace utils
} // namespace lab6

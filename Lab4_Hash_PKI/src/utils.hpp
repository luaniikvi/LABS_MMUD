#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lab4 {
namespace utils {

// Encoding
std::string to_hex(const std::vector<uint8_t>& data);
std::string to_hex(const uint8_t* data, size_t len);
std::vector<uint8_t> from_hex(const std::string& hex);

std::string to_base64(const std::vector<uint8_t>& data);
std::vector<uint8_t> from_base64(const std::string& b64);

// File I/O (binary-safe)
std::vector<uint8_t> read_file(const std::string& path);
void write_file(const std::string& path, const std::vector<uint8_t>& data);
std::string read_text_file(const std::string& path);
void write_text_file(const std::string& path, const std::string& text);

// Utilities
bool file_exists(const std::string& path);
uint64_t file_size(const std::string& path);
void fail_closed(const std::string& message);

// Byte conversion
std::vector<uint8_t> string_to_bytes(const std::string& s);
std::string bytes_to_string(const std::vector<uint8_t>& bytes);

} // namespace utils
} // namespace lab4

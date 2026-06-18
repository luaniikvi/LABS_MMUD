#include "hash_engine.hpp"
#include "x509_parser.hpp"
#include "length_ext.hpp"
#include "utils.hpp"

#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

// ============================================================================
// CLI arguments
// ============================================================================

struct CLIArgs {
    std::string command;        // hash, hmac, x509, md5-demo, length-ext, --kat
    std::string algo = "sha256";
    std::string in_file;
    std::string text;
    std::string out_file;
    std::string encode = "hex"; // hex, base64, raw
    std::string key_file;
    std::string key_hex;
    std::string cert_file;
    std::string issuer_key;
    std::string kat_file;
    std::string dir_path;       // for md5-demo
    std::string mac_hex;        // for length-ext
    std::string append_data;    // for length-ext
    int key_len = 0;            // for length-ext
    int msg_len = 0;            // for length-ext
    int outlen = 0;             // for SHAKE
    bool stream = false;
    bool verbose = false;
};

static void print_usage() {
    std::cout <<
R"(hashtool - Hashing, PKI, and Practical Attacks Tool (Lab 4)

Usage: hashtool <command> [options]

Commands:
  hash          Compute hash digest (SHA-2, SHA-3, MD5)
  hmac          Compute HMAC
  shake         Compute SHAKE (extendable output)
  x509          Parse and inspect X.509 certificate
  md5-demo      Demonstrate MD5 collision
  length-ext    Demonstrate length-extension attack on H(k||m)

Options:
  --algo ALG        Algorithm: sha224|sha256|sha384|sha512|sha3-224|sha3-256|
                    sha3-384|sha3-512|shake128|shake256|md5
  --in FILE         Input file (binary)
  --text "..."      Input text (UTF-8)
  --out FILE        Output file
  --stream          Use streaming mode for large files
  --outlen N        SHAKE output length in bytes (default: 32/64)
  --encode FORMAT   Output format: hex|base64|raw (default: hex)
  --key FILE        Key file (for HMAC)
  --key-hex HEX     Key as hex string (for HMAC)
  --cert FILE       X.509 certificate PEM file
  --issuer-key FILE Issuer public key PEM (for signature verification)
  --kat FILE        Run Known Answer Tests
  --dir DIR         Directory for md5-demo files
  --mac HEX         Original MAC hex (for length-ext)
  --key-len N       Key length in bytes (for length-ext)
  --msg-len N       Message length in bytes (for length-ext)
  --append DATA     Data to append (for length-ext)
  --verbose         Verbose output
  --help            Show this help

Examples:
  hashtool hash --algo sha256 --text "Hello World"
  hashtool hash --algo sha3-512 --in file.bin --stream
  hashtool hmac --algo sha256 --key-hex AABB --text "message"
  hashtool shake --algo shake128 --text "test" --outlen 64
  hashtool x509 --cert server.pem --issuer-key ca.pem
  hashtool md5-demo --dir demo/md5_collision
  hashtool length-ext --mac ABCDEF... --key-len 16 --msg-len 5 --append "&admin=1"
  hashtool --kat test_vectors/sha2_kats.json
)";
}

static CLIArgs parse_args(int argc, char* argv[]) {
    CLIArgs args;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage();
            std::exit(0);
        }
        else if (arg == "--algo" && i + 1 < argc) args.algo = argv[++i];
        else if (arg == "--in" && i + 1 < argc) args.in_file = argv[++i];
        else if (arg == "--text" && i + 1 < argc) args.text = argv[++i];
        else if (arg == "--out" && i + 1 < argc) args.out_file = argv[++i];
        else if (arg == "--stream") args.stream = true;
        else if (arg == "--outlen" && i + 1 < argc) args.outlen = std::stoi(argv[++i]);
        else if (arg == "--encode" && i + 1 < argc) args.encode = argv[++i];
        else if (arg == "--key" && i + 1 < argc) args.key_file = argv[++i];
        else if (arg == "--key-hex" && i + 1 < argc) args.key_hex = argv[++i];
        else if (arg == "--cert" && i + 1 < argc) args.cert_file = argv[++i];
        else if (arg == "--issuer-key" && i + 1 < argc) args.issuer_key = argv[++i];
        else if (arg == "--kat" && i + 1 < argc) { args.kat_file = argv[++i]; args.command = "--kat"; }
        else if (arg == "--dir" && i + 1 < argc) args.dir_path = argv[++i];
        else if (arg == "--mac" && i + 1 < argc) args.mac_hex = argv[++i];
        else if (arg == "--key-len" && i + 1 < argc) args.key_len = std::stoi(argv[++i]);
        else if (arg == "--msg-len" && i + 1 < argc) args.msg_len = std::stoi(argv[++i]);
        else if (arg == "--append" && i + 1 < argc) args.append_data = argv[++i];
        else if (arg == "--verbose") args.verbose = true;
        else if (arg[0] != '-' && args.command.empty()) args.command = arg;
        else {
            lab4::utils::fail_closed("Unknown argument: " + arg);
        }
    }
    return args;
}

// ============================================================================
// Format output
// ============================================================================

static std::string format_output(const std::vector<uint8_t>& data, const std::string& encode) {
    if (encode == "hex") return lab4::utils::to_hex(data);
    if (encode == "base64") return lab4::utils::to_base64(data);
    return std::string(data.begin(), data.end());
}

// ============================================================================
// Get input data
// ============================================================================

static std::vector<uint8_t> get_input(const CLIArgs& args) {
    if (!args.text.empty()) {
        return lab4::utils::string_to_bytes(args.text);
    }
    if (!args.in_file.empty()) {
        return lab4::utils::read_file(args.in_file);
    }
    lab4::utils::fail_closed("No input specified (use --in or --text)");
    return {};
}

// ============================================================================
// Command: hash
// ============================================================================

static void cmd_hash(const CLIArgs& args) {
    auto algo = lab4::hash_engine::parse_algorithm(args.algo);
    std::vector<uint8_t> digest;

    if (args.stream && !args.in_file.empty()) {
        digest = lab4::hash_engine::compute_hash_stream(algo, args.in_file);
    } else {
        auto data = get_input(args);
        digest = lab4::hash_engine::compute_hash(algo, data);
    }

    std::string result = format_output(digest, args.encode);
    std::cout << lab4::hash_engine::algorithm_name(algo) << ": " << result << std::endl;

    if (!args.out_file.empty()) {
        if (args.encode == "raw") {
            lab4::utils::write_file(args.out_file, digest);
        } else {
            lab4::utils::write_text_file(args.out_file, result);
        }
        if (args.verbose) {
            std::cout << "[INFO] Written to: " << args.out_file << std::endl;
        }
    }
}

// ============================================================================
// Command: hmac
// ============================================================================

static void cmd_hmac(const CLIArgs& args) {
    auto algo = lab4::hash_engine::parse_algorithm(args.algo);
    std::vector<uint8_t> key;

    if (!args.key_hex.empty()) {
        key = lab4::utils::from_hex(args.key_hex);
    } else if (!args.key_file.empty()) {
        key = lab4::utils::read_file(args.key_file);
    } else {
        lab4::utils::fail_closed("HMAC requires a key (--key or --key-hex)");
    }

    auto data = get_input(args);
    auto mac = lab4::hash_engine::compute_hmac(algo, key, data);

    std::string result = format_output(mac, args.encode);
    std::cout << "HMAC-" << lab4::hash_engine::algorithm_name(algo) << ": " << result << std::endl;

    if (!args.out_file.empty()) {
        if (args.encode == "raw") {
            lab4::utils::write_file(args.out_file, mac);
        } else {
            lab4::utils::write_text_file(args.out_file, result);
        }
    }
}

// ============================================================================
// Command: shake
// ============================================================================

static void cmd_shake(const CLIArgs& args) {
    auto algo = lab4::hash_engine::parse_algorithm(args.algo);
    if (algo != lab4::hash_engine::Algorithm::SHAKE128 &&
        algo != lab4::hash_engine::Algorithm::SHAKE256) {
        lab4::utils::fail_closed("SHAKE command requires --algo shake128 or shake256");
    }

    size_t outlen = (args.outlen > 0) ? static_cast<size_t>(args.outlen) : 0;
    std::vector<uint8_t> digest;

    if (args.stream && !args.in_file.empty()) {
        digest = lab4::hash_engine::compute_shake_stream(algo, args.in_file, outlen);
    } else {
        auto data = get_input(args);
        digest = lab4::hash_engine::compute_shake(algo, data, outlen);
    }

    std::string result = format_output(digest, args.encode);
    std::cout << lab4::hash_engine::algorithm_name(algo) << " ("
              << digest.size() << " bytes): " << result << std::endl;

    if (!args.out_file.empty()) {
        if (args.encode == "raw") {
            lab4::utils::write_file(args.out_file, digest);
        } else {
            lab4::utils::write_text_file(args.out_file, result);
        }
    }
}

// ============================================================================
// Command: x509
// ============================================================================

static void cmd_x509(const CLIArgs& args) {
    if (args.cert_file.empty()) {
        lab4::utils::fail_closed("X.509 command requires --cert FILE");
    }

    auto info = lab4::x509::parse_certificate(args.cert_file);
    std::cout << lab4::x509::format_cert_info(info);

    // Verify signature if issuer key provided
    if (!args.issuer_key.empty()) {
        bool valid = lab4::x509::verify_signature(args.cert_file, args.issuer_key);
        std::cout << "\nSignature Verification: "
                  << (valid ? "VALID" : "INVALID") << std::endl;
    }
}

// ============================================================================
// Command: md5-demo
// ============================================================================

static void cmd_md5_demo(const CLIArgs& args) {
    std::string dir = args.dir_path;
    if (dir.empty()) {
        // Default: relative to executable
        dir = "demo/md5_collision";
    }

    std::string file_a = dir + "/collision_a.bin";
    std::string file_b = dir + "/collision_b.bin";

    if (!lab4::utils::file_exists(file_a) || !lab4::utils::file_exists(file_b)) {
        lab4::utils::fail_closed("MD5 collision files not found in: " + dir);
    }

    auto data_a = lab4::utils::read_file(file_a);
    auto data_b = lab4::utils::read_file(file_b);

    auto md5_a = lab4::hash_engine::compute_md5(data_a);
    auto md5_b = lab4::hash_engine::compute_md5(data_b);
    auto sha256_a = lab4::hash_engine::compute_hash(lab4::hash_engine::Algorithm::SHA256, data_a);
    auto sha256_b = lab4::hash_engine::compute_hash(lab4::hash_engine::Algorithm::SHA256, data_b);

    std::cout << "========================================\n";
    std::cout << "  MD5 Collision Demonstration\n";
    std::cout << "========================================\n";
    std::cout << "File A (" << data_a.size() << " bytes): " << file_a << "\n";
    std::cout << "  MD5:    " << lab4::utils::to_hex(md5_a) << "\n";
    std::cout << "  SHA256: " << lab4::utils::to_hex(sha256_a) << "\n\n";
    std::cout << "File B (" << data_b.size() << " bytes): " << file_b << "\n";
    std::cout << "  MD5:    " << lab4::utils::to_hex(md5_b) << "\n";
    std::cout << "  SHA256: " << lab4::utils::to_hex(sha256_b) << "\n\n";

    bool md5_match = (md5_a == md5_b);
    bool sha256_match = (sha256_a == sha256_b);

    std::cout << "MD5 match:    " << (md5_match ? "YES (COLLISION!)" : "NO") << "\n";
    std::cout << "SHA-256 match: " << (sha256_match ? "YES" : "NO (different digests)") << "\n";
    std::cout << "========================================\n";
    std::cout << "\nThis demonstrates that MD5 is broken for collision resistance.\n";
    std::cout << "SHA-256 correctly distinguishes the two files.\n";
}

// ============================================================================
// Command: length-ext
// ============================================================================

static void cmd_length_ext(const CLIArgs& args) {
    if (args.mac_hex.empty() || args.key_len <= 0 || args.msg_len <= 0) {
        lab4::utils::fail_closed(
            "Length-ext requires: --mac HEX --key-len N --msg-len N --append DATA");
    }

    auto original_mac = lab4::utils::from_hex(args.mac_hex);
    std::vector<uint8_t> append_data(args.append_data.begin(), args.append_data.end());

    auto result = lab4::length_ext::extend_mac(
        original_mac, static_cast<size_t>(args.key_len),
        static_cast<size_t>(args.msg_len), append_data);

    std::cout << "========================================\n";
    std::cout << "  Length-Extension Attack on H(k||m)\n";
    std::cout << "========================================\n";
    std::cout << "Original MAC:     " << lab4::utils::to_hex(original_mac) << "\n";
    std::cout << "Key length:       " << args.key_len << " bytes\n";
    std::cout << "Message length:   " << args.msg_len << " bytes\n";
    std::cout << "Append data:      \"" << args.append_data << "\"\n";
    std::cout << "----------------------------------------\n";
    std::cout << "MD-strengthening padding:\n  " << result.padding_hex << "\n";
    std::cout << "Forged message (padding || append):\n  "
              << lab4::utils::to_hex(result.forged_message) << "\n";
    std::cout << "Forged MAC:       " << lab4::utils::to_hex(result.forged_mac) << "\n";
    std::cout << "========================================\n";
    std::cout << "\nThe attacker computed a valid MAC for an extended message\n";
    std::cout << "WITHOUT knowing the secret key.\n";
    std::cout << "This is why HMAC (not H(k||m)) must be used for MACs.\n";
}

// ============================================================================
// Command: --kat (Known Answer Tests)
// ============================================================================

static std::string get_kat_path() {
    fs::path src_dir = fs::path(__FILE__).parent_path();
    return (src_dir.parent_path() / "test_vectors").string();
}

static void cmd_kat(const std::string& kat_file) {
    std::string filepath = kat_file;
    if (!lab4::utils::file_exists(filepath)) {
        // Try relative to test_vectors directory
        filepath = get_kat_path() + "/" + kat_file;
    }
    if (!lab4::utils::file_exists(filepath)) {
        lab4::utils::fail_closed("KAT file not found: " + kat_file);
    }

    std::cout << "Running KAT: " << filepath << "\n" << std::endl;

    std::string json_str = lab4::utils::read_text_file(filepath);
    json kats = json::parse(json_str);

    int passed = 0, failed = 0;

    for (const auto& test : kats["tests"]) {
        std::string algo_name = test.value("algo", "sha256");
        std::string desc = test.value("description", "");
        int id = test.value("id", 0);

        try {
            auto algo = lab4::hash_engine::parse_algorithm(algo_name);

            // Get input
            std::vector<uint8_t> input;
            if (test.contains("input_hex")) {
                input = lab4::utils::from_hex(test["input_hex"].get<std::string>());
            } else if (test.contains("input")) {
                std::string s = test["input"].get<std::string>();
                input.assign(s.begin(), s.end());
            }

            // Compute hash
            std::vector<uint8_t> digest;
            if (algo == lab4::hash_engine::Algorithm::SHAKE128 ||
                algo == lab4::hash_engine::Algorithm::SHAKE256) {
                int outlen = test.value("outlen", 32);
                digest = lab4::hash_engine::compute_shake(algo, input, static_cast<size_t>(outlen));
            } else {
                digest = lab4::hash_engine::compute_hash(algo, input);
            }

            std::string result_hex = lab4::utils::to_hex(digest);
            std::string expected_hex = test["expected_hex"].get<std::string>();
            std::transform(expected_hex.begin(), expected_hex.end(), expected_hex.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            std::transform(result_hex.begin(), result_hex.end(), result_hex.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

            if (result_hex == expected_hex) {
                std::cout << "[PASS] #" << id << " " << desc << std::endl;
                passed++;
            } else {
                std::cout << "[FAIL] #" << id << " " << desc << std::endl;
                std::cout << "  Expected: " << expected_hex << std::endl;
                std::cout << "  Got:      " << result_hex << std::endl;
                failed++;
            }
        } catch (const std::exception& e) {
            std::cout << "[FAIL] #" << id << " " << desc << " - " << e.what() << std::endl;
            failed++;
        }
    }

    std::cout << "\n========================================\n";
    std::cout << "KAT Summary: " << passed << " passed, " << failed << " failed, "
              << (passed + failed) << " total\n";
    std::cout << "========================================\n";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    try {
        CLIArgs args = parse_args(argc, argv);

        if (args.command.empty() && args.kat_file.empty()) {
            print_usage();
            return 0;
        }

        // Check for SHAKE via algo name
        std::string algo_lower = args.algo;
        std::transform(algo_lower.begin(), algo_lower.end(), algo_lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (algo_lower.find("shake") != std::string::npos && args.command == "hash") {
            args.command = "shake";
        }

        if (args.command == "hash")       cmd_hash(args);
        else if (args.command == "hmac")  cmd_hmac(args);
        else if (args.command == "shake") cmd_shake(args);
        else if (args.command == "x509")  cmd_x509(args);
        else if (args.command == "md5-demo")    cmd_md5_demo(args);
        else if (args.command == "length-ext")  cmd_length_ext(args);
        else if (args.command == "--kat")       cmd_kat(args.kat_file);
        else {
            std::cerr << "Unknown command: " << args.command << std::endl;
            print_usage();
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

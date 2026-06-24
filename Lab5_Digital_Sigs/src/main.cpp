#include "sig_engine.hpp"
#include "utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>

#ifdef _WIN32
#include <windows.h>
#endif

using json = nlohmann::json;

using namespace lab5;

// Forward declarations
void RunKatTests(const std::string& katFilePath);

void PrintHelp() {
    std::cout << "======================================================================\n";
    std::cout << "       SIGTOOL - DIGITAL SIGNATURE TOOL (ECDSA, RSA-PSS) [LAB 5]     \n";
    std::cout << "======================================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  sigtool <command> [options]\n\n";
    std::cout << "COMMANDS:\n";
    std::cout << "  keygen              Generate signature key pair.\n";
    std::cout << "  sign                Create a detached digital signature.\n";
    std::cout << "  verify              Verify a detached digital signature.\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --algo <algo>       Algorithm: ecdsa-p256 (default), ecdsa-p384, rsa-pss-3072.\n";
    std::cout << "  --hash <hash>       Hash algorithm: sha256 (default), sha384.\n";
    std::cout << "  --pub <file>        Public key file (PEM format).\n";
    std::cout << "  --priv <file>       Private key file (PEM format).\n";
    std::cout << "  --pub-der <file>    Public key output in DER format.\n";
    std::cout << "  --priv-der <file>   Private key output in DER format.\n";
    std::cout << "  --in <file>         Path to the input file (Binary-safe).\n";
    std::cout << "  --text \"...\"        Direct input data string (UTF-8 format).\n";
    std::cout << "  --out <file>        Path to the output signature file.\n";
    std::cout << "  --sig <file>        Path to the signature file (for verify).\n";
    std::cout << "  --encode <type>     Signature encoding: der (default), hex, base64.\n";
    std::cout << "  --kat <file.json>   Path to KAT vector file.\n";
    std::cout << "  --verbose           Enable detailed logging.\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem\n";
    std::cout << "  sigtool sign --algo ecdsa-p256 --in msg.txt --out sig.der --priv priv.pem\n";
    std::cout << "  sigtool verify --algo ecdsa-p256 --in msg.txt --sig sig.der --pub pub.pem\n";
    std::cout << "  sigtool --kat test_vectors/sig_kats.json\n";
    std::cout << "======================================================================\n";
}

struct CLIArgs {
    std::string command;
    std::string algo_str = "ecdsa-p256";
    std::string hash_str = "sha256";
    std::string pub_file;
    std::string priv_file;
    std::string pub_der;
    std::string priv_der;
    std::string in_file;
    std::string out_file;
    std::string sig_file;
    std::string text;
    std::string encode = "der";
    std::string kat_file;
    bool verbose = false;
};

CLIArgs parse_args(int argc, char* argv[]) {
    CLIArgs args;

    if (argc < 2) {
        PrintHelp();
        utils::fail_closed("No command specified. Use --help for usage information.");
    }

    std::string first_arg = argv[1];
    if (first_arg == "--help" || first_arg == "-h") {
        PrintHelp();
        exit(0);
    }
    if (first_arg == "--kat") {
        if (argc < 3) {
            utils::fail_closed("--kat requires a JSON vector file path");
        }
        args.command = "kat";
        args.kat_file = argv[2];
        return args;
    }

    args.command = argv[1];

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            PrintHelp();
            exit(0);
        } else if (arg == "--algo" && i + 1 < argc) {
            args.algo_str = argv[++i];
        } else if (arg == "--hash" && i + 1 < argc) {
            args.hash_str = argv[++i];
        } else if (arg == "--pub" && i + 1 < argc) {
            args.pub_file = argv[++i];
        } else if (arg == "--priv" && i + 1 < argc) {
            args.priv_file = argv[++i];
        } else if (arg == "--pub-der" && i + 1 < argc) {
            args.pub_der = argv[++i];
        } else if (arg == "--priv-der" && i + 1 < argc) {
            args.priv_der = argv[++i];
        } else if (arg == "--in" && i + 1 < argc) {
            args.in_file = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            args.out_file = argv[++i];
        } else if (arg == "--sig" && i + 1 < argc) {
            args.sig_file = argv[++i];
        } else if (arg == "--text" && i + 1 < argc) {
            args.text = argv[++i];
        } else if (arg == "--encode" && i + 1 < argc) {
            args.encode = argv[++i];
        } else if (arg == "--kat" && i + 1 < argc) {
            args.kat_file = argv[++i];
        } else if (arg == "--verbose") {
            args.verbose = true;
        } else {
            utils::fail_closed("Unknown argument: " + arg + ". Use --help for usage information.");
        }
    }

    return args;
}

void cmd_keygen(const CLIArgs& args) {
    if (args.pub_file.empty() || args.priv_file.empty()) {
        utils::fail_closed("--pub and --priv are required for keygen");
    }

    auto algo = sig_engine::parse_algo(args.algo_str);
    sig_engine::generate_keypair(algo, args.pub_file, args.priv_file);

    // Save DER if explicitly requested
    if (!args.pub_der.empty() || !args.priv_der.empty()) {
        void* pub_key = sig_engine::load_public_key(args.pub_file, algo);
        void* priv_key = sig_engine::load_private_key(args.priv_file, algo);

        if (!args.pub_der.empty()) {
            sig_engine::save_public_key_der(pub_key, algo, args.pub_der);
            std::cout << "[INFO] DER public key saved: " << args.pub_der << std::endl;
        }
        if (!args.priv_der.empty()) {
            sig_engine::save_private_key_der(priv_key, algo, args.priv_der);
            std::cout << "[INFO] DER private key saved: " << args.priv_der << std::endl;
        }

        sig_engine::free_key(pub_key);
        sig_engine::free_key(priv_key);
    }
}

void cmd_sign(const CLIArgs& args) {
    if (args.priv_file.empty()) {
        utils::fail_closed("--priv is required for signing");
    }
    if (args.in_file.empty() && args.text.empty()) {
        utils::fail_closed("--in or --text is required for signing");
    }
    if (args.out_file.empty()) {
        utils::fail_closed("--out is required for signing");
    }

    auto algo = sig_engine::parse_algo(args.algo_str);
    auto hash = sig_engine::parse_hash(args.hash_str);
    utils::EncodeMode encode = utils::ENCODE_RAW;

    if (args.encode == "der") encode = utils::ENCODE_RAW;
    else if (args.encode == "hex") encode = utils::ENCODE_HEX;
    else if (args.encode == "base64") encode = utils::ENCODE_BASE64;
    else utils::fail_closed("Invalid --encode mode: " + args.encode + " (use der, hex, base64)");

    // Load private key
    void* priv_key = sig_engine::load_private_key(args.priv_file, algo);
    if (args.verbose) {
        std::cout << "[VERBOSE] Loaded " << sig_engine::algo_name(algo)
                  << " private key (" << sig_engine::get_key_size(priv_key, algo) << " bits)" << std::endl;
    }

    // Get message data
    std::vector<uint8_t> message;
    if (!args.text.empty()) {
        message = utils::string_to_bytes(args.text);
        if (args.verbose) {
            std::cout << "[VERBOSE] Input from text: " << message.size() << " bytes" << std::endl;
        }
    } else {
        message = utils::read_file(args.in_file);
        if (args.verbose) {
            std::cout << "[VERBOSE] Input from file: " << args.in_file << " (" << message.size() << " bytes)" << std::endl;
        }
    }

    // Sign
    auto signature = sig_engine::sign(priv_key, algo, hash, message);
    sig_engine::free_key(priv_key);

    if (args.verbose) {
        std::cout << "[VERBOSE] Signature size: " << signature.size() << " bytes" << std::endl;
    }

    // Write output
    if (encode == utils::ENCODE_HEX) {
        std::string hex = utils::to_hex(signature);
        std::cout << hex << std::endl;
        utils::write_file(args.out_file, signature);
    } else if (encode == utils::ENCODE_BASE64) {
        std::string b64 = utils::to_base64(signature);
        std::cout << b64 << std::endl;
        utils::write_file(args.out_file, signature);
    } else {
        // der (raw binary)
        utils::write_file(args.out_file, signature);
    }

    std::cout << "[INFO] Signature created: " << args.out_file << " (" << signature.size() << " bytes)" << std::endl;
}

void cmd_verify(const CLIArgs& args) {
    if (args.pub_file.empty()) {
        utils::fail_closed("--pub is required for verification");
    }
    if (args.in_file.empty() && args.text.empty()) {
        utils::fail_closed("--in or --text is required for verification");
    }
    if (args.sig_file.empty()) {
        utils::fail_closed("--sig is required for verification");
    }

    auto algo = sig_engine::parse_algo(args.algo_str);
    auto hash = sig_engine::parse_hash(args.hash_str);

    // Load public key
    void* pub_key = sig_engine::load_public_key(args.pub_file, algo);
    if (args.verbose) {
        std::cout << "[VERBOSE] Loaded " << sig_engine::algo_name(algo)
                  << " public key (" << sig_engine::get_key_size(pub_key, algo) << " bits)" << std::endl;
    }

    // Get message data
    std::vector<uint8_t> message;
    if (!args.text.empty()) {
        message = utils::string_to_bytes(args.text);
    } else {
        message = utils::read_file(args.in_file);
    }

    // Read signature
    auto signature = utils::read_file(args.sig_file);

    if (args.verbose) {
        std::cout << "[VERBOSE] Signature size: " << signature.size() << " bytes" << std::endl;
    }

    // Verify
    bool valid = sig_engine::verify(pub_key, algo, hash, message, signature);
    sig_engine::free_key(pub_key);

    if (valid) {
        std::cout << "[PASS] Signature VALID" << std::endl;
    } else {
        std::cout << "[FAIL] Signature INVALID" << std::endl;
        utils::fail_closed("Signature verification failed");
    }
}

void cmd_kat(const CLIArgs& args) {
    if (args.kat_file.empty()) {
        utils::fail_closed("--kat requires a JSON vector file path");
    }
    std::cout << "======================================================================" << std::endl;
    std::cout << "Running Known Answer Tests (KATs) from: " << args.kat_file << std::endl;
    std::cout << "======================================================================" << std::endl;
    RunKatTests(args.kat_file);
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    // Initialize OpenSSL (OpenSSL 3.0 auto-initializes for algorithms)
    OPENSSL_init_crypto(0, nullptr);

    try {
        CLIArgs args = parse_args(argc, argv);

        if (args.command == "keygen") {
            cmd_keygen(args);
        } else if (args.command == "sign") {
            cmd_sign(args);
        } else if (args.command == "verify") {
            cmd_verify(args);
        } else if (args.command == "kat") {
            cmd_kat(args);
        } else {
            utils::fail_closed("Unknown command: " + args.command + ". Use --help for usage information.");
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << std::endl;
        return 1;
    }
}

// ============================================================================
// KAT Test Runner
// ============================================================================

void RunKatTests(const std::string& katFilePath) {
    using namespace lab5;

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

    for (const auto& test : kats["tests"]) {
        total++;
        int id = test.value("id", total);
        std::string desc = test.value("description", "Test " + std::to_string(id));
        std::string expected = test.value("expected_result", "success");
        std::string algo_str = test.value("algo", "ecdsa-p256");
        std::string hash_str = test.value("hash", "sha256");

        std::vector<uint8_t> plaintext;

        if (test.contains("plaintext")) {
            plaintext = utils::string_to_bytes(test["plaintext"]);
        } else if (test.contains("plaintext_hex")) {
            plaintext = utils::from_hex(test["plaintext_hex"]);
        } else if (test.contains("plaintext_size")) {
            size_t size = test["plaintext_size"];
            plaintext = std::vector<uint8_t>(size, 0x42);
        } else {
            std::cout << "[SKIP] Test " << id << ": " << desc << " (no plaintext)" << std::endl;
            continue;
        }

        try {
            auto algo = sig_engine::parse_algo(algo_str);
            auto hash = sig_engine::parse_hash(hash_str);

            // Generate temp keypair
            std::string pub_file = "kat_pub_" + std::to_string(id) + ".pem";
            std::string priv_file = "kat_priv_" + std::to_string(id) + ".pem";

            sig_engine::generate_keypair(algo, pub_file, priv_file);

            void* priv_key = sig_engine::load_private_key(priv_file, algo);
            void* pub_key = sig_engine::load_public_key(pub_file, algo);

            auto signature = sig_engine::sign(priv_key, algo, hash, plaintext);
            bool valid = sig_engine::verify(pub_key, algo, hash, plaintext, signature);

            sig_engine::free_key(priv_key);
            sig_engine::free_key(pub_key);

            std::remove(pub_file.c_str());
            std::remove(priv_file.c_str());

            if (valid) {
                std::cout << "[PASS] Test " << id << ": " << desc << std::endl;
                passed++;
            } else {
                std::cout << "[FAIL] Test " << id << ": " << desc << " (verification failed)" << std::endl;
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

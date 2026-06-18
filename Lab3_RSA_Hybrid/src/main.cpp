#include "rsa_engine.hpp"
#include "hybrid_engine.hpp"
#include "utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

using json = nlohmann::json;
using namespace lab3;

// Forward declaration
void RunKatTests(const std::string& katFilePath);

void PrintHelp() {
    std::cout << "======================================================================\n";
    std::cout << "       RSATOOL - RSA-OAEP & HYBRID ENCRYPTION ENGINE (LAB 3)         \n";
    std::cout << "======================================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  rsatool <command> [options]\n\n";
    std::cout << "COMMANDS:\n";
    std::cout << "  keygen              Generate RSA key pair (3072 or 4096 bits).\n";
    std::cout << "  encrypt             Perform RSA-OAEP or hybrid encryption.\n";
    std::cout << "  decrypt             Perform RSA-OAEP or hybrid decryption.\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --bits <N>          Key size in bits: 3072 (default) or 4096.\n";
    std::cout << "  --in <file>         Path to the input file (Binary-safe).\n";
    std::cout << "  --text \"...\"        Direct raw input data string (UTF-8 format).\n";
    std::cout << "  --out <file>        Path to the output file (Binary-safe).\n";
    std::cout << "  --pub <file>        Public key file (PEM format).\n";
    std::cout << "  --priv <file>       Private key file (PEM format).\n";
    std::cout << "  --pub-der <file>    Public key output in DER format (auto-generated if omitted).\n";
    std::cout << "  --priv-der <file>   Private key output in DER format (auto-generated if omitted).\n";
    std::cout << "  --label <str>       Optional OAEP label for encryption/decryption.\n";
    std::cout << "  --aad <file>        Additional Authenticated Data from binary file.\n";
    std::cout << "  --aad-text <str>    Additional Authenticated Data as UTF-8 string.\n";
    std::cout << "  --encode <type>     Output encoding: hex (default), base64, raw.\n";
    std::cout << "  --kat <file.json>   Path to NIST Known Answer Tests vector file.\n";
    std::cout << "  --threads <N>       Number of threads for benchmarking (default: auto).\n";
    std::cout << "  --verbose           Enable detailed cryptographic processing logs.\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem\n";
    std::cout << "  rsatool encrypt --in msg.txt --pub pub.pem --out ct.bin\n";
    std::cout << "  rsatool encrypt --text \"Hello!\" --pub pub.pem --out ct.bin\n";
    std::cout << "  rsatool decrypt --in ct.bin --priv priv.pem --out msg.txt\n";
    std::cout << "  rsatool encrypt --in large.bin --pub pub.pem --out env.bin --aad-text \"metadata\"\n";
    std::cout << "  rsatool --kat test_vectors/rsa_oaep_kats.json\n";
    std::cout << "======================================================================\n";
}

struct CLIArgs {
    std::string command;
    int bits = 3072;
    std::string pub_file;
    std::string priv_file;
    std::string pub_der;
    std::string priv_der;
    std::string in_file;
    std::string out_file;
    std::string text;
    std::string label;
    std::string aad_file;
    std::string aad_text;
    std::string encode = "hex";
    std::string kat_file;
    int threads = 0; // 0 = auto-detect
    bool verbose = false;
};

CLIArgs parse_args(int argc, char* argv[]) {
    CLIArgs args;
    
    if (argc < 2) {
        PrintHelp();
        utils::fail_closed("No command specified. Use --help for usage information.");
    }
    
    // Check if first argument is a global flag (not a command)
    std::string first_arg = argv[1];
    if (first_arg == "--help" || first_arg == "-h") {
        PrintHelp();
        exit(0);
    }
    // Handle --kat as first argument: rsatool --kat path/to/vectors.json
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
        } else if (arg == "--bits" && i + 1 < argc) {
            args.bits = std::stoi(argv[++i]);
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
        } else if (arg == "--text" && i + 1 < argc) {
            args.text = argv[++i];
        } else if (arg == "--label" && i + 1 < argc) {
            args.label = argv[++i];
        } else if (arg == "--aad" && i + 1 < argc) {
            args.aad_file = argv[++i];
        } else if (arg == "--aad-text" && i + 1 < argc) {
            args.aad_text = argv[++i];
        } else if (arg == "--encode" && i + 1 < argc) {
            args.encode = argv[++i];
        } else if (arg == "--kat" && i + 1 < argc) {
            args.kat_file = argv[++i];
        } else if (arg == "--threads" && i + 1 < argc) {
            args.threads = std::stoi(argv[++i]);
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
    
    std::string metadata_file = args.pub_file;
    size_t dot_pos = metadata_file.find_last_of('.');
    if (dot_pos != std::string::npos) {
        metadata_file = metadata_file.substr(0, dot_pos) + "_meta.json";
    } else {
        metadata_file += "_meta.json";
    }
    
    rsa_engine::generate_keypair(args.bits, args.pub_file, args.priv_file, metadata_file);
    
    // Also save DER format (requirement: must save PEM and DER)
    auto pub_key = rsa_engine::load_public_key_pem(args.pub_file);
    auto priv_key = rsa_engine::load_private_key_pem(args.priv_file);
    
    std::string pub_der = args.pub_der;
    if (pub_der.empty()) {
        // Auto-generate DER filename from PEM filename
        pub_der = args.pub_file;
        size_t d = pub_der.find_last_of('.');
        pub_der = (d != std::string::npos ? pub_der.substr(0, d) : pub_der) + ".der";
    }
    
    std::string priv_der = args.priv_der;
    if (priv_der.empty()) {
        priv_der = args.priv_file;
        size_t d = priv_der.find_last_of('.');
        priv_der = (d != std::string::npos ? priv_der.substr(0, d) : priv_der) + ".der";
    }
    
    rsa_engine::save_public_key_der(pub_key, pub_der);
    rsa_engine::save_private_key_der(priv_key, priv_der);
    
    std::cout << "[INFO] DER public key: " << pub_der << std::endl;
    std::cout << "[INFO] DER private key: " << priv_der << std::endl;
}

void cmd_encrypt(const CLIArgs& args) {
    if (args.pub_file.empty()) {
        utils::fail_closed("--pub is required for encryption");
    }
    if (args.in_file.empty() && args.text.empty()) {
        utils::fail_closed("--in or --text is required for encryption");
    }
    if (args.out_file.empty()) {
        utils::fail_closed("--out is required for encryption");
    }
    
    // Validate encode mode
    if (args.encode != "hex" && args.encode != "base64" && args.encode != "raw") {
        utils::fail_closed("Invalid --encode mode. Use: hex, base64, or raw");
    }
    
    // Load public key
    auto pub_key = rsa_engine::load_public_key(args.pub_file);
    if (args.verbose) {
        std::cout << "[VERBOSE] Loaded RSA-" << pub_key.GetModulus().BitCount() << " public key" << std::endl;
    }
    
    // Get input data
    std::vector<uint8_t> plaintext;
    if (!args.text.empty()) {
        plaintext = utils::string_to_bytes(args.text);
        if (args.verbose) {
            std::cout << "[VERBOSE] Input from text: " << plaintext.size() << " bytes" << std::endl;
        }
    } else {
        plaintext = utils::read_file(args.in_file);
        if (args.verbose) {
            std::cout << "[VERBOSE] Input from file: " << args.in_file << " (" << plaintext.size() << " bytes)" << std::endl;
        }
    }
    
    // Get AAD if specified
    std::vector<uint8_t> aad;
    if (!args.aad_file.empty()) {
        aad = utils::read_file(args.aad_file);
        if (args.verbose) {
            std::cout << "[VERBOSE] AAD from file: " << args.aad_file << " (" << aad.size() << " bytes)" << std::endl;
        }
    } else if (!args.aad_text.empty()) {
        aad = utils::string_to_bytes(args.aad_text);
        if (args.verbose) {
            std::cout << "[VERBOSE] AAD from text: " << aad.size() << " bytes" << std::endl;
        }
    }
    
    // Check if we need hybrid mode
    size_t max_size = rsa_engine::get_max_plaintext_size(pub_key.GetModulus().BitCount());
    
    if (plaintext.size() <= max_size && aad.empty()) {
        // Direct RSA-OAEP encryption
        if (args.verbose) {
            std::cout << "[VERBOSE] Using direct RSA-OAEP encryption (plaintext <= " << max_size << " bytes)" << std::endl;
        }
        auto ciphertext = rsa_engine::encrypt(pub_key, plaintext, args.label);
        
        // Write output
        if (args.encode == "hex") {
            std::string hex = utils::to_hex(ciphertext);
            std::cout << hex << std::endl;
            if (!args.out_file.empty()) {
                utils::write_file(args.out_file, ciphertext);
            }
        } else if (args.encode == "base64") {
            std::string b64 = utils::to_base64(ciphertext);
            std::cout << b64 << std::endl;
            if (!args.out_file.empty()) {
                utils::write_file(args.out_file, ciphertext);
            }
        } else {
            // raw mode - only write to file
            utils::write_file(args.out_file, ciphertext);
        }
        
        std::cout << "[INFO] Encrypted " << plaintext.size() << " bytes -> " << ciphertext.size() << " bytes" << std::endl;
    } else {
        // Hybrid encryption
        if (args.verbose) {
            std::cout << "[VERBOSE] Using hybrid encryption (RSA-OAEP + AES-GCM)" << std::endl;
        }
        hybrid_engine::encrypt_hybrid(pub_key, plaintext, args.out_file, args.label, aad);
    }
}

void cmd_decrypt(const CLIArgs& args) {
    if (args.priv_file.empty()) {
        utils::fail_closed("--priv is required for decryption");
    }
    if (args.in_file.empty()) {
        utils::fail_closed("--in is required for decryption");
    }
    if (args.out_file.empty()) {
        utils::fail_closed("--out is required for decryption");
    }
    
    // Load private key
    auto priv_key = rsa_engine::load_private_key(args.priv_file);
    if (args.verbose) {
        std::cout << "[VERBOSE] Loaded RSA-" << priv_key.GetModulus().BitCount() << " private key" << std::endl;
    }
    
    // Try to load as envelope first
    try {
        if (args.verbose) {
            std::cout << "[VERBOSE] Attempting hybrid decryption..." << std::endl;
        }
        hybrid_engine::decrypt_hybrid(priv_key, args.in_file, args.out_file, args.label);
    } catch (const std::exception& /*e*/) {
        // Fallback to direct RSA-OAEP decryption
        if (args.verbose) {
            std::cout << "[VERBOSE] Not a hybrid envelope, trying direct RSA-OAEP..." << std::endl;
        }
        
        auto ciphertext = utils::read_file(args.in_file);
        auto plaintext = rsa_engine::decrypt(priv_key, ciphertext, args.label);
        
        utils::write_file(args.out_file, plaintext);
        std::cout << "[INFO] Decrypted " << ciphertext.size() << " bytes -> " << plaintext.size() << " bytes" << std::endl;
    }
    
    std::cout << "[INFO] Output saved to: " << args.out_file << std::endl;
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
    // Set console to UTF-8 on Windows for proper Unicode support
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    
    try {
        CLIArgs args = parse_args(argc, argv);
        
        if (args.command == "keygen") {
            cmd_keygen(args);
        } else if (args.command == "encrypt") {
            cmd_encrypt(args);
        } else if (args.command == "decrypt") {
            cmd_decrypt(args);
        } else if (args.command == "--kat" || args.command == "kat") {
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

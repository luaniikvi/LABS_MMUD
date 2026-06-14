// main.cpp
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <stdint.h>
#include <algorithm>
#include <set>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "crypto_engine.hpp"
#include "utils.hpp"

// Forward declaration of the KAT runner function from utils
void RunKatTest(const std::string& katFilePath);

void PrintHelp() {
    std::cout << "======================================================================\n";
    std::cout << "       AESTOOL - COMPREHENSIVE AES CLI SYMMETRIC ENGINE (LAB 1)       \n";
    std::cout << "======================================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  aestool <command> [options]\n\n";
    std::cout << "COMMANDS:\n";
    std::cout << "  encrypt             Perform symmetric encryption (Plaintext -> Ciphertext).\n";
    std::cout << "  decrypt             Perform symmetric decryption (Ciphertext -> Plaintext).\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --in <file>         Path to the input file (Binary-safe).\n";
    std::cout << "  --text \"...\"        Direct raw input data string (UTF-8 format).\n";
    std::cout << "  --out <file>        Path to the output file (Binary-safe).\n";
    std::cout << "  --key <file>        Key file (raw binary or hex-encoded with header).\n";
    std::cout << "  --key-hex <hex>     Cryptographic cipher key encoded in Hex format.\n";
    std::cout << "  --iv <file|hex>     IV/nonce file (binary/hex header) or inline hex string.\n";
    std::cout << "  --nonce <file|hex>  Alias for --iv.\n";
    std::cout << "  --aad <file>        Additional Authenticated Data read from a binary file.\n";
    std::cout << "  --aad-text <str>    Additional Authenticated Data as a raw UTF-8 string.\n";
    std::cout << "  --mode <MODE>       Supported cipher modes: ecb, cbc, ctr, ofb, cfb, xts, gcm, ccm\n";
    std::cout << "  --aead              Enable strict AEAD authentication validation.\n";
    std::cout << "  --encode <type>     On-screen output encoding: hex, base64, base, raw (Default: hex).\n";
    std::cout << "  --threads <N>       Number of execution threads to use (Default: 1).\n";
    std::cout << "  --kat <file.json>   Path to the NIST Known Answer Tests (KAT) vector file.\n";
    std::cout << "  --verbose           Enable detailed cryptographic processing telemetry logs.\n";
    std::cout << "  --allow-ecb         Bypass built-in safety constraints for ECB on large data.\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin --aead\n";
    std::cout << "  aestool decrypt --mode gcm --key key.bin --in ct.bin --out msg.txt --aead\n";
    std::cout << "  aestool --kat vectors.json\n";
    std::cout << "======================================================================\n";
}

int main(int argc, char* argv[]) {
    // Set console to UTF-8 on Windows for proper Unicode support
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    
    if (argc < 2) {
        PrintHelp();
        return 1;
    }

    std::string firstArg = argv[1];
    if (firstArg == "--help" || firstArg == "-h" || firstArg == "-help") {
        PrintHelp();
        return 0;
    }

    CryptoConfig config;
    std::string command = "";
    std::string textInput, inFile, outFile, tagHex, katPath;
    bool hasText = false;

    // Strict Whitelist validation for CLI arguments to ensure "Fail-Closed" behavior
    std::set<std::string> validArguments = {
        "--in", "--text", "--out", "--key", "--key-hex", "--iv", "--nonce",
        "--aad", "--aad-text", "--mode", "--aead", "--encode", "--threads", "--kat",
        "--verbose", "--allow-ecb", "--tag-hex"
    };

    bool hasAadFile = false;
    bool hasAadText = false;

    try {
        // Parse command line arguments starting from index 1 to handle all options and commands dynamically
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];

            // If argument starts with '-'
            if (arg.rfind("-", 0) == 0) {
                if (validArguments.count(arg) == 0) {
                    throw std::runtime_error("Invalid or unrecognized option provided: " + arg);
                }

                // Parse flags and validate presence of values (Throw if missing value)
                if (arg == "--kat") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --kat");
                    katPath = argv[++i]; 
                    command = "--kat"; 
                }
                else if (arg == "--mode") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --mode");
                    config.mode = argv[++i];
                }
                else if (arg == "--key-hex") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --key-hex");
                    config.key = FromHex(argv[++i]);
                }
                else if (arg == "--key") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --key");
                    config.key = ReadBinaryOrHexFile(argv[++i]);
                }
                else if (arg == "--iv" || arg == "--nonce") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for " + arg);
                    config.iv = LoadIvOrNonceArg(argv[++i]);
                }
                else if (arg == "--aad") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --aad");
                    std::string aadFile = argv[++i];
                    std::ifstream af(aadFile, std::ios::binary);
                    if (!af) throw std::runtime_error("I/O Error: Failed to open the AAD file: " + aadFile);
                    config.aad.assign((std::istreambuf_iterator<char>(af)), std::istreambuf_iterator<char>());
                    hasAadFile = true;
                }
                else if (arg == "--aad-text") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --aad-text");
                    config.aad = argv[++i];
                    hasAadText = true;
                }
                else if (arg == "--text") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --text");
                    textInput = argv[++i]; 
                    hasText = true; 
                }
                else if (arg == "--in") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --in");
                    inFile = argv[++i];
                }
                else if (arg == "--out") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --out");
                    outFile = argv[++i];
                }
                else if (arg == "--tag-hex") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --tag-hex");
                    tagHex = argv[++i];
                }
                else if (arg == "--aead") {
                    config.isAead = true;
                }
                else if (arg == "--verbose") {
                    config.verbose = true;
                }
                else if (arg == "--allow-ecb") {
                    config.allowEcb = true;
                }
                else if (arg == "--threads") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --threads");
                    config.threads = std::stoi(argv[++i]);
                }
                else if (arg == "--encode") {
                    if (i + 1 >= argc) throw std::runtime_error("Missing parameter value for --encode");
                    config.encodeMode = argv[++i];
                    if (config.encodeMode != "hex" && config.encodeMode != "base64" && config.encodeMode != "base" && config.encodeMode != "raw") {
                        throw std::runtime_error("Invalid encode mode specified: " + config.encodeMode);
                    }
                }
            } else {
                // If it doesn't start with "-", it must be the command (encrypt/decrypt)
                if (arg == "encrypt" || arg == "decrypt") {
                    if (!command.empty() && command != "--kat") {
                        throw std::runtime_error("Multiple commands specified: " + command + " and " + arg);
                    }
                    if (command != "--kat") {
                        command = arg;
                    }
                } else {
                    throw std::runtime_error("Unexpected positional argument: " + arg);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[FAIL-SECURE] CLI configuration error: " << e.what() << "\n";
        return 1;
    }

    if (command == "--kat") {
        RunKatTest(katPath);
        return 0;
    }

    if (command != "encrypt" && command != "decrypt") {
        std::cerr << "[ERROR] Invalid command. Use 'aestool --help' to display options.\n";
        return 1;
    }

    // Auto-load metadata from sidecar .json if decoding from an input file
    if (command == "decrypt" && !inFile.empty()) {
        std::string sidecarPath = inFile + ".json";
        std::ifstream sidecarFile(sidecarPath);
        if (sidecarFile.is_open()) {
            try {
                nlohmann::json s;
                sidecarFile >> s;
                if (config.iv.empty() && s.contains("iv") && !s["iv"].get<std::string>().empty()) {
                    config.iv = FromHex(s["iv"].get<std::string>());
                }
                if (tagHex.empty() && s.contains("tag") && !s["tag"].get<std::string>().empty()) {
                    tagHex = s["tag"].get<std::string>();
                }
                if (config.aad.empty() && s.contains("aad") && !s["aad"].get<std::string>().empty()) {
                    std::vector<uint8_t> aadBytes = FromHex(s["aad"].get<std::string>());
                    config.aad.assign(aadBytes.begin(), aadBytes.end());
                }
                if (config.mode.empty() && s.contains("mode") && !s["mode"].get<std::string>().empty()) {
                    config.mode = s["mode"].get<std::string>();
                }
                if (config.mode.empty() && s.contains("alg")) {
                    std::string alg = s["alg"].get<std::string>();
                    size_t lastDash = alg.find_last_of('-');
                    if (lastDash != std::string::npos) {
                        config.mode = alg.substr(lastDash + 1);
                    }
                }
                if ((config.mode == "gcm" || config.mode == "ccm") && !config.isAead) {
                    config.isAead = true;
                }
                if (config.verbose) {
                    std::cout << "[INFO] Sidecar metadata loaded: " << sidecarPath << "\n";
                }
            } catch (...) {
                // Ignore parse errors, fall back to explicit CLI arguments
            }
        }
    }

    if (config.mode.empty()) {
        std::cerr << "[ERROR] The '--mode' parameter is required for execution!\n";
        return 1;
    }

    if (hasAadFile && hasAadText) {
        std::cerr << "[FAIL-SECURE] Cannot specify both --aad and --aad-text.\n";
        return 1;
    }

    const bool isAeadMode = (config.mode == "gcm" || config.mode == "ccm");
    if (isAeadMode && !config.isAead) {
        std::cerr << "[FAIL-SECURE] AEAD modes (gcm, ccm) require the --aead flag.\n";
        return 1;
    }
    if (config.isAead && !isAeadMode) {
        std::cerr << "[FAIL-SECURE] --aead is only valid with gcm or ccm modes.\n";
        return 1;
    }

    try {
        std::vector<uint8_t> inputData;
        if (hasText) {
            inputData = StringToBytes(textInput);
        } else if (!inFile.empty()) {
            std::ifstream f(inFile, std::ios::binary);
            if (!f) throw std::runtime_error("I/O Error: Failed to open the input file!");
            inputData.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        } else {
            std::cerr << "[ERROR] Missing input data source. Please provide '--text' or '--in'.\n";
            return 1;
        }

        if (command == "encrypt") {
            std::vector<uint8_t> tag;
            std::vector<uint8_t> ciphertext = EncryptAES(inputData, config, tag);

            if (!outFile.empty()) {
                const std::string ivHexOut = ToHex(config.iv);
                const std::string tagHexOut = ToHex(tag);
                const std::string aadHexOut = ToHex(std::vector<uint8_t>(config.aad.begin(), config.aad.end()));

                {
                    std::ofstream out(outFile, std::ios::binary);
                    if (!out) {
                        throw std::runtime_error("I/O Error: Failed to open output file: " + outFile);
                    }
                    if (!ciphertext.empty()) {
                        out.write(reinterpret_cast<const char*>(ciphertext.data()), static_cast<std::streamsize>(ciphertext.size()));
                    }
                }

                WriteSidecarJSON(outFile, "AES-" + std::to_string(config.key.size() * 8) + "-" + config.mode,
                                 config.mode, ivHexOut, tagHexOut, aadHexOut);
                RegisterKeyNonceUse(config);
                if (config.verbose) {
                    std::cout << "[INFO] Sidecar metadata written: " << outFile << ".json\n";
                    std::cout << "[SUCCESS] Binary output file generated: " << outFile << "\n";
                }
            } else {
                if (config.encodeMode == "base64" || config.encodeMode == "base") {
                    std::cout << ToBase64(ciphertext) << "\n";
                } else if (config.encodeMode == "raw") {
                    std::cout.write((const char*)ciphertext.data(), ciphertext.size());
                } else {
                    std::cout << ToHex(ciphertext) << "\n";
                }

                if (config.mode != "ecb" && !config.iv.empty()) {
                    std::cout << "[IV-HEX]: " << ToHex(config.iv) << "\n";
                }
                if (!tag.empty() && config.isAead) {
                    std::cout << "[TAG-HEX]: " << ToHex(tag) << "\n";
                }
                RegisterKeyNonceUse(config);
            }
        } 
        else if (command == "decrypt") {
            if (config.isAead && tagHex.empty()) {
                throw std::runtime_error("AEAD decryption requires an authentication tag (--tag-hex or sidecar .json)!");
            }
            std::vector<uint8_t> tag = tagHex.empty() ? std::vector<uint8_t>{} : FromHex(tagHex);
            std::vector<uint8_t> plaintext = DecryptAES(inputData, config, tag);

            if (!outFile.empty()) {
                std::ofstream out(outFile, std::ios::binary);
                out.write((const char*)plaintext.data(), plaintext.size());
                std::cout << "[SUCCESS] Decryption complete! Plaintext saved to: " << outFile << "\n";
            } else {
                // Ensure the output stream processes valid UTF-8 plaintext cleanly
                std::string outStr(plaintext.begin(), plaintext.end());
                std::cout << outStr << "\n";
            }
        }
    } 
    catch (const std::exception& e) {
        std::cerr << "[FAIL-SECURE] Process terminated due to safety/validation error: " << e.what() << "\n";
        return 1; 
    }

    return 0;
}
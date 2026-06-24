#include "pq_engine.hpp"
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
using namespace lab6;

void RunKatTests(const std::string& katFilePath);

void PrintHelp() {
    std::cout << "======================================================================\n";
    std::cout << "       PQTOOL - POST-QUANTUM CRYPTO TOOL (ML-DSA, ML-KEM) [LAB 6]    \n";
    std::cout << "======================================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  pqtool <command> [options]\n\n";
    std::cout << "COMMANDS:\n";
    std::cout << "  keygen             Generate PQC key pair (ML-DSA or ML-KEM).\n";
    std::cout << "  sign               Create ML-DSA signature.\n";
    std::cout << "  verify             Verify ML-DSA signature.\n";
    std::cout << "  encaps             ML-KEM encapsulation.\n";
    std::cout << "  decaps             ML-KEM decapsulation.\n";
    std::cout << "  cert               PQ Certificate operations (sign/verify).\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --algo <algo>      Algorithm: mldsa-44 (default), mldsa-65, mlkem-512.\n";
    std::cout << "  --hash <hash>      Hash algorithm: sha256 (default), sha384.\n";
    std::cout << "  --pub <file>       Public key file (PEM format).\n";
    std::cout << "  --priv <file>      Private key file (PEM format).\n";
    std::cout << "  --ca-pub <file>    CA public key file (for cert verify).\n";
    std::cout << "  --ca-priv <file>   CA private key file (for cert sign).\n";
    std::cout << "  --subject <str>    Subject name (for cert).\n";
    std::cout << "  --in <file>        Input file (binary-safe).\n";
    std::cout << "  --text \"...\"       Direct input data (UTF-8).\n";
    std::cout << "  --out <file>       Output file.\n";
    std::cout << "  --sig <file>       Signature file (for verify).\n";
    std::cout << "  --ct <file>        Ciphertext file (for decapsulate).\n";
    std::cout << "  --ss <file>        Shared secret output file.\n";
    std::cout << "  --encode <type>    Encoding: der (default), hex, base64.\n";
    std::cout << "  --kat <file.json>  Path to KAT vector file.\n";
    std::cout << "  --threads <N>      Threads for parallel operations (default: auto).\n";
    std::cout << "  --verbose          Enable detailed logging.\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem\n";
    std::cout << "  pqtool sign --algo mldsa-44 --in msg.bin --out sig.bin --priv priv.pem\n";
    std::cout << "  pqtool verify --algo mldsa-44 --in msg.bin --sig sig.bin --pub pub.pem\n";
    std::cout << "  pqtool keygen --algo mlkem-512 --pub kem_pub.pem --priv kem_priv.pem\n";
    std::cout << "  pqtool encaps --algo mlkem-512 --pub kem_pub.pem --ct ct.bin --ss ss.bin\n";
    std::cout << "  pqtool decaps --algo mlkem-512 --priv kem_priv.pem --ct ct.bin --ss ss.bin\n";
    std::cout << "  pqtool cert --ca-priv ca.pem --subject-pub sub.pem --subject \"Alice\" --out cert.json\n";
    std::cout << "  pqtool --kat test_vectors/pq_kats.json\n";
    std::cout << "======================================================================\n";
}

struct CLIArgs {
    std::string command;
    std::string algo_str = "mldsa-44";
    std::string hash_str = "sha256";
    std::string pub_file;
    std::string priv_file;
    std::string ca_pub;
    std::string ca_priv;
    std::string subject_pub;
    std::string subject_name;
    std::string in_file;
    std::string out_file;
    std::string sig_file;
    std::string ct_file;
    std::string ss_file;
    std::string text;
    std::string encode = "raw";
    std::string kat_file;
    int threads = 0;
    bool verbose = false;
};

CLIArgs parse_args(int argc, char* argv[]) {
    CLIArgs args;
    if (argc < 2) { PrintHelp(); utils::fail_closed("No command specified."); }

    std::string first_arg = argv[1];
    if (first_arg == "--help" || first_arg == "-h") { PrintHelp(); exit(0); }
    if (first_arg == "--kat") {
        if (argc < 3) utils::fail_closed("--kat requires a JSON vector file path");
        args.command = "kat";
        args.kat_file = argv[2];
        return args;
    }

    args.command = argv[1];
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { PrintHelp(); exit(0); }
        else if (arg == "--algo" && i + 1 < argc) { args.algo_str = argv[++i]; }
        else if (arg == "--hash" && i + 1 < argc) { args.hash_str = argv[++i]; }
        else if (arg == "--pub" && i + 1 < argc) { args.pub_file = argv[++i]; }
        else if (arg == "--priv" && i + 1 < argc) { args.priv_file = argv[++i]; }
        else if (arg == "--ca-pub" && i + 1 < argc) { args.ca_pub = argv[++i]; }
        else if (arg == "--ca-priv" && i + 1 < argc) { args.ca_priv = argv[++i]; }
        else if (arg == "--subject-pub" && i + 1 < argc) { args.subject_pub = argv[++i]; }
        else if (arg == "--subject" && i + 1 < argc) { args.subject_name = argv[++i]; }
        else if (arg == "--in" && i + 1 < argc) { args.in_file = argv[++i]; }
        else if (arg == "--out" && i + 1 < argc) { args.out_file = argv[++i]; }
        else if (arg == "--sig" && i + 1 < argc) { args.sig_file = argv[++i]; }
        else if (arg == "--ct" && i + 1 < argc) { args.ct_file = argv[++i]; }
        else if (arg == "--ss" && i + 1 < argc) { args.ss_file = argv[++i]; }
        else if (arg == "--text" && i + 1 < argc) { args.text = argv[++i]; }
        else if (arg == "--encode" && i + 1 < argc) { args.encode = argv[++i]; }
        else if (arg == "--kat" && i + 1 < argc) { args.kat_file = argv[++i]; }
        else if (arg == "--threads" && i + 1 < argc) { args.threads = std::stoi(argv[++i]); }
        else if (arg == "--verbose") { args.verbose = true; }
        else { utils::fail_closed("Unknown argument: " + arg); }
    }
    return args;
}

void cmd_keygen(const CLIArgs& args) {
    if (args.pub_file.empty() || args.priv_file.empty())
        utils::fail_closed("--pub and --priv are required for keygen");
    auto algo = pq_engine::parse_algo(args.algo_str);
    pq_engine::generate_keypair(algo, args.pub_file, args.priv_file);
}

void cmd_sign(const CLIArgs& args) {
    if (args.priv_file.empty()) utils::fail_closed("--priv is required for signing");
    if (args.in_file.empty() && args.text.empty()) utils::fail_closed("--in or --text is required");
    if (args.out_file.empty()) utils::fail_closed("--out is required for signing");

    auto algo = pq_engine::parse_algo(args.algo_str);
    auto hash = pq_engine::parse_hash(args.hash_str);
    if (!pq_engine::is_ml_dsa(algo))
        utils::fail_closed("sign/verify only supports ML-DSA algorithms");

    void* priv_key = pq_engine::load_private_key(args.priv_file, algo);
    if (args.verbose)
        std::cout << "[VERBOSE] Loaded " << pq_engine::algo_name(algo) << " private key" << std::endl;

    std::vector<uint8_t> message;
    if (!args.text.empty()) message = utils::string_to_bytes(args.text);
    else message = utils::read_file(args.in_file);

    auto signature = pq_engine::sign(priv_key, algo, hash, message);
    pq_engine::free_key(priv_key);

    utils::write_file(args.out_file, signature);
    std::cout << "[INFO] Signature created: " << args.out_file << " (" << signature.size() << " bytes)" << std::endl;
}

void cmd_verify(const CLIArgs& args) {
    if (args.pub_file.empty()) utils::fail_closed("--pub is required for verification");
    if (args.in_file.empty() && args.text.empty()) utils::fail_closed("--in or --text is required");
    if (args.sig_file.empty()) utils::fail_closed("--sig is required for verification");

    auto algo = pq_engine::parse_algo(args.algo_str);
    auto hash = pq_engine::parse_hash(args.hash_str);

    void* pub_key = pq_engine::load_public_key(args.pub_file, algo);
    std::vector<uint8_t> message;
    if (!args.text.empty()) message = utils::string_to_bytes(args.text);
    else message = utils::read_file(args.in_file);
    auto signature = utils::read_file(args.sig_file);

    bool valid = pq_engine::verify(pub_key, algo, hash, message, signature);
    pq_engine::free_key(pub_key);

    if (valid) { std::cout << "[PASS] Signature VALID" << std::endl; }
    else { std::cout << "[FAIL] Signature INVALID" << std::endl; utils::fail_closed("Verification failed"); }
}

void cmd_encaps(const CLIArgs& args) {
    if (args.pub_file.empty()) utils::fail_closed("--pub is required for encapsulation");
    if (args.ct_file.empty() || args.ss_file.empty())
        utils::fail_closed("--ct and --ss are required for encapsulation");

    auto algo = pq_engine::parse_algo(args.algo_str);
    if (!pq_engine::is_ml_kem(algo))
        utils::fail_closed("encaps/decaps only supports ML-KEM algorithms");

    void* pub_key = pq_engine::load_public_key(args.pub_file, algo);
    auto [ct, ss] = pq_engine::encapsulate(pub_key, algo);
    pq_engine::free_key(pub_key);

    utils::write_file(args.ct_file, ct);
    utils::write_file(args.ss_file, ss);
    std::cout << "[INFO] KEM encapsulation complete" << std::endl;
    std::cout << "[INFO] Ciphertext (" << ct.size() << " bytes): " << args.ct_file << std::endl;
    std::cout << "[INFO] Shared secret (" << ss.size() << " bytes): " << args.ss_file << std::endl;
}

void cmd_decaps(const CLIArgs& args) {
    if (args.priv_file.empty()) utils::fail_closed("--priv is required for decapsulation");
    if (args.ct_file.empty() || args.ss_file.empty())
        utils::fail_closed("--ct and --ss are required for decapsulation");

    auto algo = pq_engine::parse_algo(args.algo_str);
    if (!pq_engine::is_ml_kem(algo))
        utils::fail_closed("encaps/decaps only supports ML-KEM algorithms");

    void* priv_key = pq_engine::load_private_key(args.priv_file, algo);
    auto ct = utils::read_file(args.ct_file);
    auto ss = pq_engine::decapsulate(priv_key, algo, ct);
    pq_engine::free_key(priv_key);

    utils::write_file(args.ss_file, ss);
    std::cout << "[INFO] KEM decapsulation complete" << std::endl;
    std::cout << "[INFO] Shared secret (" << ss.size() << " bytes): " << args.ss_file << std::endl;
}

void cmd_cert(const CLIArgs& args) {
    // cert command: sign a subject public key with a CA private key
    if (args.command == "cert" && args.ca_priv.empty() && args.ca_pub.empty())
        utils::fail_closed("cert requires --ca-priv (sign) or --ca-pub (verify)");

    if (!args.ca_priv.empty()) {
        // Sign: CA signs subject's public key
        if (args.subject_pub.empty() || args.subject_name.empty() || args.out_file.empty())
            utils::fail_closed("cert sign requires --ca-priv, --subject-pub, --subject, --out");

        void* ca_priv = pq_engine::load_private_key(args.ca_priv, pq_engine::PQAlgo::ML_DSA_44);
        auto subject_pub_data = utils::read_text_file(args.subject_pub);

        json cert;
        cert["subject"] = args.subject_name;
        cert["public_key"] = utils::to_base64(
            std::vector<uint8_t>(subject_pub_data.begin(), subject_pub_data.end()));
        cert["issuer"] = "PQ-CA";
        cert["algorithm"] = "ML-DSA-44";

        // Sign the subject + public key structure
        std::string tbs = args.subject_name + subject_pub_data;
        auto tbs_bytes = std::vector<uint8_t>(tbs.begin(), tbs.end());
        auto signature = pq_engine::sign(ca_priv, pq_engine::PQAlgo::ML_DSA_44, pq_engine::HashAlgo::SHA256, tbs_bytes);
        pq_engine::free_key(ca_priv);

        cert["signature"] = utils::to_hex(signature);

        utils::write_text_file(args.out_file, cert.dump(2));
        std::cout << "[INFO] PQ Certificate created: " << args.out_file << std::endl;
    } else if (!args.ca_pub.empty()) {
        // Verify
        if (args.in_file.empty())
            utils::fail_closed("cert verify requires --ca-pub and --in <cert.json>");

        auto cert_text = utils::read_text_file(args.in_file);
        json cert = json::parse(cert_text);

        std::string subject = cert["subject"];
        std::string pubkey_b64 = cert["public_key"];
        std::string sig_hex = cert["signature"];
        std::string issuer = cert.value("issuer", "unknown");

        auto pubkey_data = utils::from_base64(pubkey_b64);
        std::string pubkey_str(pubkey_data.begin(), pubkey_data.end());

        std::string tbs = subject + pubkey_str;
        auto tbs_bytes = std::vector<uint8_t>(tbs.begin(), tbs.end());
        auto signature = utils::from_hex(sig_hex);

        // Write pubkey to temp file for loading
        std::string tmp_pub = "_pq_cert_pub.pem";
        utils::write_text_file(tmp_pub, pubkey_str);
        void* pub_key = pq_engine::load_public_key(tmp_pub, pq_engine::PQAlgo::ML_DSA_44);
        std::remove(tmp_pub.c_str());

        bool valid = pq_engine::verify(pub_key, pq_engine::PQAlgo::ML_DSA_44, pq_engine::HashAlgo::SHA256, tbs_bytes, signature);
        pq_engine::free_key(pub_key);

        std::cout << "[INFO] PQ Certificate Verification" << std::endl;
        std::cout << "  Subject: " << subject << std::endl;
        std::cout << "  Issuer: " << issuer << std::endl;
        if (valid) {
            std::cout << "[PASS] Certificate signature VALID" << std::endl;
        } else {
            std::cout << "[FAIL] Certificate signature INVALID" << std::endl;
        }
    }
}

void cmd_kat(const CLIArgs& args) {
    if (args.kat_file.empty()) utils::fail_closed("--kat requires a JSON vector file path");
    std::cout << "======================================================================" << std::endl;
    std::cout << "Running Known Answer Tests (KATs) from: " << args.kat_file << std::endl;
    std::cout << "======================================================================" << std::endl;
    RunKatTests(args.kat_file);
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8); SetConsoleCP(CP_UTF8);
#endif
    OPENSSL_init_crypto(0, nullptr);
    try {
        CLIArgs args = parse_args(argc, argv);
        if (args.command == "keygen") cmd_keygen(args);
        else if (args.command == "sign") cmd_sign(args);
        else if (args.command == "verify") cmd_verify(args);
        else if (args.command == "encaps") cmd_encaps(args);
        else if (args.command == "decaps") cmd_decaps(args);
        else if (args.command == "cert") cmd_cert(args);
        else if (args.command == "kat") cmd_kat(args);
        else utils::fail_closed("Unknown command: " + args.command);
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
    using namespace lab6;
    std::string json_str = utils::read_text_file(katFilePath);
    json kats = json::parse(json_str);
    std::cout << "\nAlgorithm: " << kats.value("algorithm", "Unknown") << std::endl;
    std::cout << "Description: " << kats.value("description", "Unknown") << std::endl;
    std::cout << "\nRunning tests...\n" << std::endl;
    int passed = 0, failed = 0, total = 0;

    for (const auto& test : kats["tests"]) {
        total++;
        int id = test.value("id", total);
        std::string desc = test.value("description", "Test " + std::to_string(id));
        std::string expected = test.value("expected_result", "success");
        std::string algo_str = test.value("algo", "mldsa-44");

        try {
            auto algo = pq_engine::parse_algo(algo_str);
            auto hash = pq_engine::HashAlgo::SHA256;

            std::string pub_file = "kat_pub_" + std::to_string(id) + ".pem";
            std::string priv_file = "kat_priv_" + std::to_string(id) + ".pem";
            pq_engine::generate_keypair(algo, pub_file, priv_file);

            bool result_ok = false;
            if (pq_engine::is_ml_dsa(algo)) {
                std::vector<uint8_t> plaintext;
                if (test.contains("plaintext"))
                    plaintext = utils::string_to_bytes(test["plaintext"]);
                else if (test.contains("plaintext_size"))
                    plaintext = std::vector<uint8_t>((size_t)test["plaintext_size"], 0x42);
                else
                    plaintext = {};

                void* priv_key = pq_engine::load_private_key(priv_file, algo);
                void* pub_key = pq_engine::load_public_key(pub_file, algo);
                auto signature = pq_engine::sign(priv_key, algo, hash, plaintext);
                result_ok = pq_engine::verify(pub_key, algo, hash, plaintext, signature);
                pq_engine::free_key(priv_key);
                pq_engine::free_key(pub_key);
            } else {
                // ML-KEM: encaps/decaps roundtrip
                void* priv_key = pq_engine::load_private_key(priv_file, algo);
                void* pub_key = pq_engine::load_public_key(pub_file, algo);
                auto [ct, ss1] = pq_engine::encapsulate(pub_key, algo);
                auto ss2 = pq_engine::decapsulate(priv_key, algo, ct);
                result_ok = (ss1 == ss2);
                pq_engine::free_key(priv_key);
                pq_engine::free_key(pub_key);
            }

            std::remove(pub_file.c_str());
            std::remove(priv_file.c_str());
            // Also clean auto-generated DER files
            std::string pd = pub_file; pd.replace(pd.find_last_of('.'), 4, ".der");
            std::string rd = priv_file; rd.replace(rd.find_last_of('.'), 5, ".der");
            std::remove(pd.c_str()); std::remove(rd.c_str());

            if (result_ok) { std::cout << "[PASS] Test " << id << ": " << desc << std::endl; passed++; }
            else { std::cout << "[FAIL] Test " << id << ": " << desc << std::endl; failed++; }

        } catch (const std::exception& e) {
            if (expected == "fail") { std::cout << "[PASS] Test " << id << ": " << desc << " (expected failure)" << std::endl; passed++; }
            else { std::cout << "[FAIL] Test " << id << ": " << desc << " (" << e.what() << ")" << std::endl; failed++; }
        }
    }

    std::cout << "\n======================================================================" << std::endl;
    std::cout << "KAT Summary" << std::endl;
    std::cout << "Total tests: " << total << std::endl;
    std::cout << "Passed:      " << passed << std::endl;
    std::cout << "Failed:      " << failed << std::endl;
    std::cout << "Success rate: " << (total > 0 ? (passed * 100.0 / total) : 0) << "%" << std::endl;
    std::cout << "======================================================================" << std::endl;
}

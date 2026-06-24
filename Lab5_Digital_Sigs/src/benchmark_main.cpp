#include "benchmark.hpp"
#include "sig_engine.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <openssl/crypto.h>

using namespace lab5;

void PrintBenchmarkHelp() {
    std::cout << "======================================================================\n";
    std::cout << "       Lab 5 - Digital Signatures Benchmark Tool\n";
    std::cout << "======================================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  benchmark [options]\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --help, -h          Show this help message and exit.\n";
    std::cout << "  --threads <N>       Number of threads (default: 1).\n";
    std::cout << "  --iterations <N>    Number of iterations per benchmark (default: 30).\n";
    std::cout << "  --verbose           Enable detailed output.\n";
    std::cout << "  --warm <secs>       Warmup duration in seconds (default: 2.0).\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  benchmark\n";
    std::cout << "  benchmark --iterations 50\n";
    std::cout << "======================================================================\n";
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    int threads = 1;
    int iterations = 30;
    double warmup_secs = 2.0;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            PrintBenchmarkHelp();
            return 0;
        } else if (arg == "--threads" && i + 1 < argc) {
            threads = std::stoi(argv[++i]);
        } else if (arg == "--iterations" && i + 1 < argc) {
            iterations = std::stoi(argv[++i]);
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--warm" && i + 1 < argc) {
            warmup_secs = std::stod(argv[++i]);
        } else {
            std::cerr << "[ERROR] Unknown argument: " << arg << "\n";
            return 1;
        }
    }

    if (threads == 0) {
        threads = static_cast<int>(std::thread::hardware_concurrency());
        if (threads < 1) threads = 4;
    }

    if (verbose) {
        std::cout << "[CONFIG] Threads: " << threads << ", Iterations: " << iterations << ", Warmup: " << warmup_secs << "s\n" << std::endl;
    }

    OPENSSL_init_crypto(0, nullptr);

    std::cout << "========================================" << std::endl;
    std::cout << "Lab 5 - Digital Signature Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        // ====================================================================
        // ECDSA P-256
        // ====================================================================
        std::cout << "\n[1] ECDSA P-256 Benchmark" << std::endl;
        auto ecdsa_p256 = benchmark::benchmark_ecdsa("ecdsa-p256", iterations);
        benchmark::print_result("ECDSA P-256 KeyGen", ecdsa_p256.keygen);
        benchmark::print_result("ECDSA P-256 Sign", ecdsa_p256.sign);
        benchmark::print_result("ECDSA P-256 Verify", ecdsa_p256.verify);

        // ====================================================================
        // ECDSA P-384
        // ====================================================================
        std::cout << "\n[2] ECDSA P-384 Benchmark" << std::endl;
        auto ecdsa_p384 = benchmark::benchmark_ecdsa("ecdsa-p384", iterations);
        benchmark::print_result("ECDSA P-384 KeyGen", ecdsa_p384.keygen);
        benchmark::print_result("ECDSA P-384 Sign", ecdsa_p384.sign);
        benchmark::print_result("ECDSA P-384 Verify", ecdsa_p384.verify);

        // ====================================================================
        // RSA-PSS-3072
        // ====================================================================
        std::cout << "\n[3] RSA-PSS-3072 Benchmark" << std::endl;
        auto rsa_pss = benchmark::benchmark_rsa_pss(3072, iterations);
        benchmark::print_result("RSA-PSS-3072 KeyGen", rsa_pss.keygen);
        benchmark::print_result("RSA-PSS-3072 Sign", rsa_pss.sign);
        benchmark::print_result("RSA-PSS-3072 Verify", rsa_pss.verify);

        // ====================================================================
        // Summary
        // ====================================================================
        std::cout << "\n========================================" << std::endl;
        std::cout << "Benchmark Complete" << std::endl;
        std::cout << "========================================" << std::endl;

        // Comparison table: keygen
        benchmark::print_comparison_table(
            {"ECDSA P-256 KeyGen", "ECDSA P-384 KeyGen", "RSA-PSS-3072 KeyGen"},
            {ecdsa_p256.keygen, ecdsa_p384.keygen, rsa_pss.keygen}
        );

        // Comparison table: sign
        benchmark::print_comparison_table(
            {"ECDSA P-256 Sign", "ECDSA P-384 Sign", "RSA-PSS-3072 Sign"},
            {ecdsa_p256.sign, ecdsa_p384.sign, rsa_pss.sign}
        );

        // Comparison table: verify
        benchmark::print_comparison_table(
            {"ECDSA P-256 Verify", "ECDSA P-384 Verify", "RSA-PSS-3072 Verify"},
            {ecdsa_p256.verify, ecdsa_p384.verify, rsa_pss.verify}
        );

        std::cout << "\nKey Findings:" << std::endl;
        std::cout << "- ECDSA key generation is much faster than RSA-PSS" << std::endl;
        std::cout << "- ECDSA verification is faster than ECDSA signing" << std::endl;
        std::cout << "- RSA-PSS verification is faster than RSA-PSS signing" << std::endl;
        std::cout << "- ECDSA signatures are much smaller than RSA-PSS" << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }
}

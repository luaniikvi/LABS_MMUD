#include "benchmark.hpp"
#include "pq_engine.hpp"
#include <iostream>
#include <thread>
#include <openssl/crypto.h>

using namespace lab6;

void PrintBenchmarkHelp() {
    std::cout << "======================================================================\n";
    std::cout << "       Lab 6 - Post-Quantum Cryptography Benchmark Tool\n";
    std::cout << "======================================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  benchmark [options]\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --help, -h          Show help.\n";
    std::cout << "  --iterations <N>    Iterations per benchmark (default: 30).\n";
    std::cout << "  --threads <N>       Thread count (default: 1, 0=auto).\n";
    std::cout << "  --verbose           Enable detailed output.\n";
    std::cout << "  --warm <secs>       Warmup duration in seconds (default: 2.0).\n";
    std::cout << "======================================================================\n";
}

int main(int argc, char* argv[]) {
    int iterations = 30;
    int threads = 1;
    double warmup_secs = 2.0;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { PrintBenchmarkHelp(); return 0; }
        else if (arg == "--iterations" && i + 1 < argc) iterations = std::stoi(argv[++i]);
        else if (arg == "--threads" && i + 1 < argc) threads = std::stoi(argv[++i]);
        else if (arg == "--verbose") verbose = true;
        else if (arg == "--warm" && i + 1 < argc) warmup_secs = std::stod(argv[++i]);
        else { std::cerr << "[ERROR] Unknown argument: " << arg << "\n"; return 1; }
    }

    if (threads == 0) {
        threads = static_cast<int>(std::thread::hardware_concurrency());
        if (threads < 1) threads = 4;
    }

    if (verbose) {
        std::cout << "[CONFIG] Iterations: " << iterations << ", Threads: " << threads << ", Warmup: " << warmup_secs << "s\n" << std::endl;
    }

    OPENSSL_init_crypto(0, nullptr);

    std::cout << "========================================" << std::endl;
    std::cout << "Lab 6 - Post-Quantum Cryptography Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        std::cout << "\n[1] ML-DSA-44 Benchmark" << std::endl;
        auto dsa44 = lab6::benchmark::benchmark_mldsa("mldsa-44", iterations);
        lab6::benchmark::print_result("ML-DSA-44 KeyGen", dsa44.keygen);
        lab6::benchmark::print_result("ML-DSA-44 Sign", dsa44.sign);
        lab6::benchmark::print_result("ML-DSA-44 Verify", dsa44.verify);

        std::cout << "\n[2] ML-DSA-65 Benchmark" << std::endl;
        auto dsa65 = lab6::benchmark::benchmark_mldsa("mldsa-65", iterations);
        lab6::benchmark::print_result("ML-DSA-65 KeyGen", dsa65.keygen);
        lab6::benchmark::print_result("ML-DSA-65 Sign", dsa65.sign);
        lab6::benchmark::print_result("ML-DSA-65 Verify", dsa65.verify);

        std::cout << "\n[3] ML-KEM-512 Benchmark" << std::endl;
        auto kem512 = lab6::benchmark::benchmark_mlkem("mlkem-512", iterations);
        lab6::benchmark::print_result("ML-KEM-512 KeyGen", kem512.keygen);
        lab6::benchmark::print_result("ML-KEM-512 Encaps", kem512.encaps);
        lab6::benchmark::print_result("ML-KEM-512 Decaps", kem512.decaps);

        lab6::benchmark::print_comparison_table(
            {"ML-DSA-44 KeyGen", "ML-DSA-65 KeyGen", "ML-KEM-512 KeyGen"},
            {dsa44.keygen, dsa65.keygen, kem512.keygen}
        );
        lab6::benchmark::print_comparison_table(
            {"ML-DSA-44 Sign", "ML-DSA-65 Sign"},
            {dsa44.sign, dsa65.sign}
        );
        lab6::benchmark::print_comparison_table(
            {"ML-DSA-44 Verify", "ML-DSA-65 Verify"},
            {dsa44.verify, dsa65.verify}
        );

        std::cout << "\nKey Findings:" << std::endl;
        std::cout << "- ML-DSA signatures are much larger than ECDSA (~2.5 KiB for ML-DSA-44)" << std::endl;
        std::cout << "- ML-KEM encapsulation/decapsulation is fast" << std::endl;
        std::cout << "- ML-DSA key generation is relatively fast" << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }
}

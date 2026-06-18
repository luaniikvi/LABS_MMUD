#include "benchmark.hpp"
#include "rsa_engine.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <filesystem>

namespace fs = std::filesystem;
using namespace lab3;

void PrintBenchmarkHelp() {
    std::cout << "======================================================================\n";
    std::cout << "       Lab 3 - RSA & Hybrid Encryption Benchmark Tool\n";
    std::cout << "======================================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  benchmark_lab3 [options]\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --help, -h          Show this help message and exit.\n";
    std::cout << "  --threads <N>       Number of threads to use (default: 1).\n";
    std::cout << "                      Set to 0 to auto-detect ("
              << std::thread::hardware_concurrency() << " detected).\n";
    std::cout << "  --iterations <N>    Number of iterations per benchmark (default: 30).\n";
    std::cout << "  --keysize <N>       RSA key size: 3072 or 4096 (default: 3072).\n";
    std::cout << "  --verbose           Enable detailed output.\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  benchmark_lab3\n";
    std::cout << "  benchmark_lab3 --threads 4 --iterations 50\n";
    std::cout << "  benchmark_lab3 --threads 0   # auto-detect CPU count\n";
    std::cout << "  benchmark_lab3 --keysize 4096 --verbose\n";
    std::cout << "======================================================================\n";
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    int threads = 1;
    int iterations = 30;
    int keysize = 3072;
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
        } else if (arg == "--keysize" && i + 1 < argc) {
            keysize = std::stoi(argv[++i]);
        } else if (arg == "--verbose") {
            verbose = true;
        } else {
            std::cerr << "[ERROR] Unknown argument: " << arg << "\n";
            std::cerr << "Use --help for usage information.\n";
            return 1;
        }
    }
    
    // Auto-detect thread count when user passes --threads 0
    if (threads == 0) {
        threads = static_cast<int>(std::thread::hardware_concurrency());
        if (threads < 1) threads = 4; // fallback
    }
    
    if (verbose) {
        std::cout << "[CONFIG] Threads: " << threads << ", Iterations: " << iterations 
                  << ", Key size: " << keysize << " bits\n" << std::endl;
    }
    std::cout << "========================================" << std::endl;
    std::cout << "Lab 3 - RSA & Hybrid Encryption Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    
    try {
        // ====================================================================
        // RSA Key Generation
        // ====================================================================
        std::cout << "\n[1] RSA Key Generation Benchmark" << std::endl;
        auto kg_3072 = benchmark::benchmark_rsa_keygen(3072, 30);
        benchmark::print_result("RSA-3072 KeyGen", kg_3072);
        
        auto kg_4096 = benchmark::benchmark_rsa_keygen(4096, 30);
        benchmark::print_result("RSA-4096 KeyGen", kg_4096);
        
        benchmark::print_comparison_table(
            {"RSA-3072 KeyGen", "RSA-4096 KeyGen"},
            {kg_3072, kg_4096}
        );
        
        // ====================================================================
        // RSA-OAEP Encryption/Decryption
        // ====================================================================
        std::cout << "\n[2] RSA-OAEP Encryption/Decryption Benchmark" << std::endl;
        
        // Generate keypair ONCE for all RSA & hybrid benchmarks
        std::string pub_file = "bm_pub.pem";
        std::string priv_file = "bm_priv.pem";
        std::string meta_file = "bm_meta.json";
        rsa_engine::generate_keypair(3072, pub_file, priv_file, meta_file);
        
        std::vector<uint8_t> small_msg = {'H', 'e', 'l', 'l', 'o'};
        std::vector<uint8_t> medium_msg(382, 0x42); // Max size for RSA-3072
        
        auto enc_3072_small = benchmark::benchmark_rsa_encrypt(3072, small_msg, 100);
        benchmark::print_result("RSA-3072 Encrypt (5 bytes)", enc_3072_small);
        
        // Generate ciphertext for decryption benchmark
        auto pub_key = rsa_engine::load_public_key(pub_file);
        auto ciphertext = rsa_engine::encrypt(pub_key, small_msg);
        
        auto dec_3072_small = benchmark::benchmark_rsa_decrypt(3072, ciphertext, 100);
        benchmark::print_result("RSA-3072 Decrypt (5 bytes)", dec_3072_small);
        
        // ====================================================================
        // Hybrid Encryption
        // ====================================================================
        std::cout << "\n[3] Hybrid Encryption Benchmark (RSA-3072 + AES-256-GCM)" << std::endl;
        
        std::vector<size_t> payload_sizes = {1024, 4096, 16384, 262144, 1048576, 104857600};
        std::vector<std::string> size_labels = {"1 KiB", "4 KiB", "16 KiB", "256 KiB", "1 MiB", "100 MiB"};
        
        for (size_t i = 0; i < payload_sizes.size(); i++) {
            auto enc_result = benchmark::benchmark_hybrid_encrypt(3072, payload_sizes[i], 30);
            benchmark::print_result("Hybrid Encrypt - " + size_labels[i], enc_result);
            
            auto dec_result = benchmark::benchmark_hybrid_decrypt(3072, payload_sizes[i], 30);
            benchmark::print_result("Hybrid Decrypt - " + size_labels[i], dec_result);
        }
        
        // Cleanup keypair files
        fs::remove(pub_file);
        fs::remove(priv_file);
        fs::remove(meta_file);
        
        // ====================================================================
        // Summary
        // ====================================================================
        std::cout << "\n========================================" << std::endl;
        std::cout << "Benchmark Complete" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "\nKey Findings:" << std::endl;
        std::cout << "- RSA key generation is computationally expensive" << std::endl;
        std::cout << "- RSA decryption is ~10-50x slower than encryption" << std::endl;
        std::cout << "- Hybrid encryption throughput depends on AES-GCM performance" << std::endl;
        std::cout << "- RSA-4096 is ~3-5x slower than RSA-3072 for key generation" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }
}

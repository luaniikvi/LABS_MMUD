#include "benchmark.hpp"
#include "rsa_engine.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;
using namespace lab3;

int main() {
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
        
        std::vector<uint8_t> small_msg = {'H', 'e', 'l', 'l', 'o'};
        std::vector<uint8_t> medium_msg(382, 0x42); // Max size for RSA-3072
        
        auto enc_3072_small = benchmark::benchmark_rsa_encrypt(3072, small_msg, 100);
        benchmark::print_result("RSA-3072 Encrypt (5 bytes)", enc_3072_small);
        
        // Generate ciphertext for decryption benchmark
        std::string pub_file = "bm_pub.pem";
        std::string priv_file = "bm_priv.pem";
        std::string meta_file = "bm_meta.json";
        rsa_engine::generate_keypair(3072, pub_file, priv_file, meta_file);
        auto pub_key = rsa_engine::load_public_key(pub_file);
        auto ciphertext = rsa_engine::encrypt(pub_key, small_msg);
        
        auto dec_3072_small = benchmark::benchmark_rsa_decrypt(3072, ciphertext, 100);
        benchmark::print_result("RSA-3072 Decrypt (5 bytes)", dec_3072_small);
        
        // Cleanup
        fs::remove(pub_file);
        fs::remove(priv_file);
        fs::remove(meta_file);
        
        // ====================================================================
        // Hybrid Encryption
        // ====================================================================
        std::cout << "\n[3] Hybrid Encryption Benchmark (RSA-3072 + AES-256-GCM)" << std::endl;
        
        std::vector<size_t> payload_sizes = {1024, 4096, 16384, 262144, 1048576};
        std::vector<std::string> size_labels = {"1 KiB", "4 KiB", "16 KiB", "256 KiB", "1 MiB"};
        
        for (size_t i = 0; i < payload_sizes.size(); i++) {
            auto enc_result = benchmark::benchmark_hybrid_encrypt(3072, payload_sizes[i], 30);
            benchmark::print_result("Hybrid Encrypt - " + size_labels[i], enc_result);
            
            auto dec_result = benchmark::benchmark_hybrid_decrypt(3072, payload_sizes[i], 30);
            benchmark::print_result("Hybrid Decrypt - " + size_labels[i], dec_result);
        }
        
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

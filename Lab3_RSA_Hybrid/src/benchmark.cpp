#include "benchmark.hpp"
#include "rsa_engine.hpp"
#include "hybrid_engine.hpp"
#include "utils.hpp"
#include <filesystem>
#include <iostream>

using namespace lab3;

namespace fs = std::filesystem;

namespace lab3 {
namespace benchmark {

double calculate_mean(const std::vector<double>& data) {
    double sum = std::accumulate(data.begin(), data.end(), 0.0);
    return sum / data.size();
}

double calculate_median(std::vector<double> data) {
    std::sort(data.begin(), data.end());
    size_t n = data.size();
    if (n % 2 == 0) {
        return (data[n/2 - 1] + data[n/2]) / 2.0;
    } else {
        return data[n/2];
    }
}

double calculate_std_dev(const std::vector<double>& data, double mean) {
    double sq_sum = 0.0;
    for (double val : data) {
        sq_sum += (val - mean) * (val - mean);
    }
    return std::sqrt(sq_sum / data.size());
}

double calculate_ci95(const std::vector<double>& data, double mean) {
    double std_dev = calculate_std_dev(data, mean);
    // 95% CI = mean ± 1.96 * (std_dev / sqrt(n))
    return 1.96 * (std_dev / std::sqrt(data.size()));
}

void warmup(double seconds) {
    auto start = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double>(seconds);
    
    while (std::chrono::high_resolution_clock::now() - start < duration) {
        CryptoPP::AutoSeededRandomPool rng;
        std::vector<uint8_t> dummy(1024);
        rng.GenerateBlock(dummy.data(), dummy.size());
    }
}

BenchmarkResult benchmark_rsa_keygen(int bits, int num_runs) {
    std::cout << "\n[BM] RSA-" << bits << " Key Generation (" << num_runs << " runs)..." << std::endl;
    warmup();
    
    std::vector<double> times;
    std::string pub_file = "bm_pub.pem";
    std::string priv_file = "bm_priv.pem";
    std::string meta_file = "bm_meta.json";
    
    for (int i = 0; i < num_runs; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        
        rsa_engine::generate_keypair(bits, pub_file, priv_file, meta_file);
        
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(elapsed_ms);
        
        if (i % 10 == 0) {
            std::cout << "\r[BM] Run " << (i+1) << "/" << num_runs << std::flush;
        }
    }
    std::cout << std::endl;
    
    fs::remove(pub_file);
    fs::remove(priv_file);
    fs::remove(meta_file);
    
    BenchmarkResult result;
    result.num_runs = num_runs;
    result.mean_ms = calculate_mean(times);
    result.median_ms = calculate_median(times);
    result.std_dev_ms = calculate_std_dev(times, result.mean_ms);
    result.ci95_ms = calculate_ci95(times, result.mean_ms);
    result.throughput_mbps = 0;
    
    return result;
}

BenchmarkResult benchmark_rsa_encrypt(int bits, const std::vector<uint8_t>& plaintext, int num_runs) {
    std::cout << "\n[BM] RSA-" << bits << " Encryption (" << num_runs << " runs)..." << std::endl;
    warmup();
    
    // Use existing keypair files (must already exist)
    std::string pub_file = "bm_pub.pem";
    auto pub_key = rsa_engine::load_public_key(pub_file);
    
    std::vector<double> times;
    
    for (int i = 0; i < num_runs; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        
        auto ciphertext = rsa_engine::encrypt(pub_key, plaintext);
        
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(elapsed_ms);
        
        if (i % 100 == 0) {
            std::cout << "\r[BM] Run " << (i+1) << "/" << num_runs << std::flush;
        }
    }
    std::cout << std::endl;
    
    BenchmarkResult result;
    result.num_runs = num_runs;
    result.mean_ms = calculate_mean(times);
    result.median_ms = calculate_median(times);
    result.std_dev_ms = calculate_std_dev(times, result.mean_ms);
    result.ci95_ms = calculate_ci95(times, result.mean_ms);
    result.throughput_mbps = 0;
    
    return result;
}

BenchmarkResult benchmark_rsa_decrypt(int bits, const std::vector<uint8_t>& ciphertext, int num_runs) {
    std::cout << "\n[BM] RSA-" << bits << " Decryption (" << num_runs << " runs)..." << std::endl;
    warmup();
    
    // Use existing keypair files (must already exist)
    std::string priv_file = "bm_priv.pem";
    auto priv_key = rsa_engine::load_private_key(priv_file);
    
    std::vector<double> times;
    
    for (int i = 0; i < num_runs; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        
        auto plaintext = rsa_engine::decrypt(priv_key, ciphertext);
        
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(elapsed_ms);
        
        if (i % 100 == 0) {
            std::cout << "\r[BM] Run " << (i+1) << "/" << num_runs << std::flush;
        }
    }
    std::cout << std::endl;
    
    BenchmarkResult result;
    result.num_runs = num_runs;
    result.mean_ms = calculate_mean(times);
    result.median_ms = calculate_median(times);
    result.std_dev_ms = calculate_std_dev(times, result.mean_ms);
    result.ci95_ms = calculate_ci95(times, result.mean_ms);
    result.throughput_mbps = 0;
    
    return result;
}

BenchmarkResult benchmark_hybrid_encrypt(int bits, size_t payload_size, int num_runs) {
    (void)bits;  // key size is determined by the pre-generated keypair file
    std::cout << "\n[BM] Hybrid Encrypt - " << payload_size << " bytes (" << num_runs << " runs)..." << std::endl;
    warmup();
    
    // Use existing keypair files (must already exist)
    std::string pub_file = "bm_pub.pem";
    auto pub_key = rsa_engine::load_public_key(pub_file);
    
    std::vector<uint8_t> plaintext(payload_size, 0xAB);
    std::string env_file = "bm_envelope.bin";
    
    std::vector<double> times;
    
    for (int i = 0; i < num_runs; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        
        hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file);
        
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(elapsed_ms);
        
        if (i % 10 == 0) {
            std::cout << "\r[BM] Run " << (i+1) << "/" << num_runs << std::flush;
        }
    }
    std::cout << std::endl;
    
    // Calculate throughput
    double mean_sec = calculate_mean(times) / 1000.0;
    
    fs::remove(env_file);
    
    BenchmarkResult result;
    result.num_runs = num_runs;
    result.mean_ms = calculate_mean(times);
    result.median_ms = calculate_median(times);
    result.std_dev_ms = calculate_std_dev(times, result.mean_ms);
    result.ci95_ms = calculate_ci95(times, result.mean_ms);
    result.throughput_mbps = (payload_size / (1024.0 * 1024.0)) / mean_sec;
    
    return result;
}

BenchmarkResult benchmark_hybrid_decrypt(int bits, size_t payload_size, int num_runs) {
    (void)bits;  // key size is determined by the pre-generated keypair file
    std::cout << "\n[BM] Hybrid Decrypt - " << payload_size << " bytes (" << num_runs << " runs)..." << std::endl;
    warmup();
    
    // Use existing keypair files (must already exist)
    std::string pub_file = "bm_pub.pem";
    std::string priv_file = "bm_priv.pem";
    auto pub_key = rsa_engine::load_public_key(pub_file);
    auto priv_key = rsa_engine::load_private_key(priv_file);
    
    std::vector<uint8_t> plaintext(payload_size, 0xCD);
    std::string env_file = "bm_envelope.bin";
    std::string out_file = "bm_output.bin";
    
    // Create envelope once
    hybrid_engine::encrypt_hybrid(pub_key, plaintext, env_file);
    
    std::vector<double> times;
    
    for (int i = 0; i < num_runs; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        
        hybrid_engine::decrypt_hybrid(priv_key, env_file, out_file);
        
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(elapsed_ms);
        
        if (i % 10 == 0) {
            std::cout << "\r[BM] Run " << (i+1) << "/" << num_runs << std::flush;
        }
    }
    std::cout << std::endl;
    
    // Calculate throughput
    double mean_sec = calculate_mean(times) / 1000.0;
    
    fs::remove(env_file);
    fs::remove(out_file);
    
    BenchmarkResult result;
    result.num_runs = num_runs;
    result.mean_ms = calculate_mean(times);
    result.median_ms = calculate_median(times);
    result.std_dev_ms = calculate_std_dev(times, result.mean_ms);
    result.ci95_ms = calculate_ci95(times, result.mean_ms);
    result.throughput_mbps = (payload_size / (1024.0 * 1024.0)) / mean_sec;
    
    return result;
}

void print_result(const std::string& label, const BenchmarkResult& result) {
    std::cout << "\n=== " << label << " ===" << std::endl;
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Runs:        " << result.num_runs << std::endl;
    std::cout << "Mean:        " << result.mean_ms << " ms" << std::endl;
    std::cout << "Median:      " << result.median_ms << " ms" << std::endl;
    std::cout << "Std Dev:     " << result.std_dev_ms << " ms" << std::endl;
    std::cout << "95% CI:      ~" << result.ci95_ms << " ms" << std::endl;
    if (result.throughput_mbps > 0) {
        std::cout << "Throughput:  " << result.throughput_mbps << " MB/s" << std::endl;
    }
}

void print_comparison_table(const std::vector<std::string>& labels, 
                           const std::vector<BenchmarkResult>& results) {
    std::cout << "\n=== Comparison Table ===" << std::endl;
    std::cout << std::left << std::setw(30) << "Operation" 
              << std::right << std::setw(12) << "Mean (ms)"
              << std::setw(12) << "Median (ms)"
              << std::setw(12) << "Std Dev"
              << std::setw(12) << "95% CI" << std::endl;
    std::cout << std::string(78, '-') << std::endl;
    
    for (size_t i = 0; i < labels.size(); i++) {
        std::cout << std::left << std::setw(30) << labels[i]
                  << std::right << std::fixed << std::setprecision(3)
                  << std::setw(12) << results[i].mean_ms
                  << std::setw(12) << results[i].median_ms
                  << std::setw(12) << results[i].std_dev_ms
                  << std::setw(12) << results[i].ci95_ms << std::endl;
    }
}

} // namespace benchmark
} // namespace lab3

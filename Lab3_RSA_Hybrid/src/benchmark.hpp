#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <iomanip>

namespace lab3 {
namespace benchmark {

struct BenchmarkResult {
    double mean_ms;
    double median_ms;
    double std_dev_ms;
    double ci95_ms;
    double throughput_mbps;
    int num_runs;
};

// Statistical calculations
double calculate_mean(const std::vector<double>& data);
double calculate_median(std::vector<double> data);
double calculate_std_dev(const std::vector<double>& data, double mean);
double calculate_ci95(const std::vector<double>& data, double mean);

// Benchmark RSA operations
BenchmarkResult benchmark_rsa_keygen(int bits, int num_runs = 30);
BenchmarkResult benchmark_rsa_encrypt(int bits, const std::vector<uint8_t>& plaintext, int num_runs = 100);
BenchmarkResult benchmark_rsa_decrypt(int bits, const std::vector<uint8_t>& ciphertext, int num_runs = 100);

// Benchmark hybrid operations
BenchmarkResult benchmark_hybrid_encrypt(int bits, size_t payload_size, int num_runs = 30);
BenchmarkResult benchmark_hybrid_decrypt(int bits, size_t payload_size, int num_runs = 30);

// Print results
void print_result(const std::string& label, const BenchmarkResult& result);
void print_comparison_table(const std::vector<std::string>& labels, 
                           const std::vector<BenchmarkResult>& results);

// Warm-up
void warmup(double seconds = 2.0);

} // namespace benchmark
} // namespace lab3

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

namespace lab5 {
namespace benchmark {

struct BenchmarkResult {
    double mean_ms;
    double median_ms;
    double std_dev_ms;
    double ci95_ms;
    double throughput_ops;
    int num_runs;
};

// Statistical calculations
double calculate_mean(const std::vector<double>& data);
double calculate_median(std::vector<double> data);
double calculate_std_dev(const std::vector<double>& data, double mean);
double calculate_ci95(const std::vector<double>& data, double mean);

// Benchmark ECDSA operations
struct ECDSABenchResult {
    BenchmarkResult keygen;
    BenchmarkResult sign;
    BenchmarkResult verify;
};

// Benchmark RSA-PSS operations
struct RSAPSSBenchResult {
    BenchmarkResult keygen;
    BenchmarkResult sign;
    BenchmarkResult verify;
};

// Run ECDSA benchmarks
ECDSABenchResult benchmark_ecdsa(const std::string& curve_name, int num_runs = 30);

// Run RSA-PSS benchmarks
RSAPSSBenchResult benchmark_rsa_pss(int bits, int num_runs = 30);

// Print results
void print_result(const std::string& label, const BenchmarkResult& result);
void print_comparison_table(const std::vector<std::string>& labels,
                           const std::vector<BenchmarkResult>& results);

// Warm-up
void warmup(double seconds = 2.0);

} // namespace benchmark
} // namespace lab5

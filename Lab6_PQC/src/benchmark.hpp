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

namespace lab6 {
namespace benchmark {

struct BenchmarkResult {
    double mean_ms;
    double median_ms;
    double std_dev_ms;
    double ci95_ms;
    double throughput_ops;
    int num_runs;
};

double calculate_mean(const std::vector<double>& data);
double calculate_median(std::vector<double> data);
double calculate_std_dev(const std::vector<double>& data, double mean);
double calculate_ci95(const std::vector<double>& data, double mean);

// ML-DSA benchmark
struct MLDSABenchResult {
    BenchmarkResult keygen;
    BenchmarkResult sign;
    BenchmarkResult verify;
};

// ML-KEM benchmark
struct MLKEMBenchResult {
    BenchmarkResult keygen;
    BenchmarkResult encaps;
    BenchmarkResult decaps;
};

MLDSABenchResult benchmark_mldsa(const std::string& algo_name, int num_runs = 30);
MLKEMBenchResult benchmark_mlkem(const std::string& algo_name, int num_runs = 30);

void print_result(const std::string& label, const BenchmarkResult& result);
void print_comparison_table(const std::vector<std::string>& labels,
                           const std::vector<BenchmarkResult>& results);
void warmup(double seconds = 2.0);

} // namespace benchmark
} // namespace lab6

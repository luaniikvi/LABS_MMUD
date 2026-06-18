#pragma once

#include <string>
#include <vector>

namespace lab4 {

struct BenchmarkResult {
    double mean_ms = 0;
    double median_ms = 0;
    double std_dev_ms = 0;
    double ci95_ms = 0;
    double throughput_mbps = 0;
    int num_runs = 0;
    size_t payload_size = 0;
    std::string algorithm;
};

// Stats helpers
double calculate_mean(const std::vector<double>& values);
double calculate_median(std::vector<double> values);
double calculate_std_dev(const std::vector<double>& values, double mean);
double calculate_ci95(const std::vector<double>& values, double mean);

// Benchmark a hash algorithm on a given payload size
BenchmarkResult benchmark_hash(const std::string& algo_name, size_t payload_size,
                                int num_runs = 30, double warmup_secs = 2.0);

// Print formatted result
void print_result(const BenchmarkResult& r);
void print_comparison_table(const std::vector<BenchmarkResult>& results);

} // namespace lab4

#include "benchmark.hpp"
#include "hash_engine.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <numeric>
#include <random>

namespace lab4 {

// ============================================================================
// Statistics
// ============================================================================

double calculate_mean(const std::vector<double>& values) {
    if (values.empty()) return 0;
    return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
}

double calculate_median(std::vector<double> values) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    size_t n = values.size();
    if (n % 2 == 0) {
        return (values[n/2 - 1] + values[n/2]) / 2.0;
    }
    return values[n/2];
}

double calculate_std_dev(const std::vector<double>& values, double mean) {
    if (values.size() < 2) return 0;
    double sum_sq = 0;
    for (double v : values) {
        double diff = v - mean;
        sum_sq += diff * diff;
    }
    return std::sqrt(sum_sq / values.size());
}

double calculate_ci95(const std::vector<double>& values, double mean) {
    if (values.size() < 2) return 0;
    double sd = calculate_std_dev(values, mean);
    return 1.96 * sd / std::sqrt(static_cast<double>(values.size()));
}

// ============================================================================
// Warmup: hash random data for warm_secs seconds
// ============================================================================

static void warmup(double warm_secs = 2.0) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::duration<double>(warm_secs);
    std::vector<uint8_t> buf(4096, 0x42);
    while (std::chrono::steady_clock::now() < deadline) {
        hash_engine::compute_hash(hash_engine::Algorithm::SHA256, buf);
    }
}

// ============================================================================
// Benchmark a hash algorithm
// ============================================================================

BenchmarkResult benchmark_hash(const std::string& algo_name, size_t payload_size,
                                int num_runs, double warmup_secs) {
    std::cout << "\n[BM] " << algo_name << " - " << payload_size
              << " bytes (" << num_runs << " runs)..." << std::endl;

    warmup(warmup_secs);

    // Generate random payload
    std::vector<uint8_t> payload(payload_size);
    std::mt19937 rng(42); // deterministic seed for reproducibility
    for (size_t i = 0; i < payload_size; i++) {
        payload[i] = static_cast<uint8_t>(rng() & 0xFF);
    }

    auto algo = hash_engine::parse_algorithm(algo_name);
    std::vector<double> times;
    times.reserve(num_runs);

    for (int i = 0; i < num_runs; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        hash_engine::compute_hash(algo, payload);
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        times.push_back(elapsed_ms);

        if (i % 10 == 0) {
            std::cout << "\r[BM] Run " << (i+1) << "/" << num_runs << std::flush;
        }
    }
    std::cout << std::endl;

    double mean = calculate_mean(times);

    BenchmarkResult result;
    result.algorithm = algo_name;
    result.payload_size = payload_size;
    result.num_runs = num_runs;
    result.mean_ms = mean;
    result.median_ms = calculate_median(times);
    result.std_dev_ms = calculate_std_dev(times, mean);
    result.ci95_ms = calculate_ci95(times, mean);

    // Throughput in MB/s
    double mean_sec = mean / 1000.0;
    if (mean_sec > 0) {
        result.throughput_mbps = (static_cast<double>(payload_size) / (1024.0 * 1024.0)) / mean_sec;
    }

    return result;
}

// ============================================================================
// Display
// ============================================================================

void print_result(const BenchmarkResult& r) {
    std::cout << "  Algorithm:   " << r.algorithm << "\n";
    std::cout << "  Payload:     " << r.payload_size << " bytes\n";
    std::cout << "  Runs:        " << r.num_runs << "\n";
    std::cout << "  Mean:        " << std::fixed << std::setprecision(4) << r.mean_ms << " ms\n";
    std::cout << "  Median:      " << r.median_ms << " ms\n";
    std::cout << "  Std Dev:     " << r.std_dev_ms << " ms\n";
    std::cout << "  CI 95%:      +/- " << r.ci95_ms << " ms\n";
    std::cout << "  Throughput:  " << std::setprecision(2) << r.throughput_mbps << " MB/s\n";
}

void print_comparison_table(const std::vector<BenchmarkResult>& results) {
    std::cout << "\n";
    std::cout << std::left << std::setw(14) << "Algorithm"
              << std::right << std::setw(12) << "Payload"
              << std::setw(12) << "Mean(ms)"
              << std::setw(12) << "Median(ms)"
              << std::setw(12) << "StdDev"
              << std::setw(12) << "CI95"
              << std::setw(14) << "Throughput" << "\n";
    std::cout << std::string(88, '-') << "\n";

    for (const auto& r : results) {
        std::cout << std::left << std::setw(14) << r.algorithm
                  << std::right << std::setw(12) << r.payload_size
                  << std::fixed << std::setprecision(4)
                  << std::setw(12) << r.mean_ms
                  << std::setw(12) << r.median_ms
                  << std::setw(12) << r.std_dev_ms
                  << std::setw(12) << r.ci95_ms
                  << std::setprecision(2) << std::setw(11) << r.throughput_mbps
                  << " MB/s\n";
    }
}

} // namespace lab4

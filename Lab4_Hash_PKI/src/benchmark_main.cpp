#include "benchmark.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#endif

static void print_usage() {
    std::cout <<
R"(hashtool benchmark - Hash Performance Benchmark

Usage: benchmark [options]

Options:
  --help, -h        Show this help message and exit.
  --threads <N>     Number of threads to use (default: 1).
                    Set to 0 to auto-detect.
  --iterations N    Number of runs per test (default: 30)
  --warm SECS       Warmup duration in seconds (default: 2.0)
  --verbose         Verbose output
)";
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    int iterations = 30;
    double warmup_secs = 2.0;
    int threads = 1;
    bool verbose = false;

    if (argc == 1) {
        print_usage();
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { print_usage(); return 0; }
        else if (arg == "--threads" && i + 1 < argc) threads = std::stoi(argv[++i]);
        else if (arg == "--iterations" && i + 1 < argc) iterations = std::stoi(argv[++i]);
        else if (arg == "--warm" && i + 1 < argc) warmup_secs = std::stod(argv[++i]);
        else if (arg == "--verbose") verbose = true;
        else { std::cerr << "[ERROR] Unknown argument: " << arg << std::endl; return 1; }
    }

    if (threads == 0) {
        threads = static_cast<int>(std::thread::hardware_concurrency());
        if (threads < 1) threads = 4;
    }

    std::cout << "========================================\n";
    std::cout << "  Lab 4 - Hash Performance Benchmark\n";
    std::cout << "========================================\n";
    std::cout << "Iterations: " << iterations << "\n";
    std::cout << "Warmup:     " << warmup_secs << "s\n";
    std::cout << "Threads:    " << threads << "\n\n";

    // Algorithms to benchmark
    std::vector<std::string> algos = {"sha256", "sha512", "sha3-256", "sha3-512"};

    // Payload sizes
    std::vector<size_t> sizes = {
        1024,        // 1 KiB
        102400,      // 100 KiB
        1048576,     // 1 MiB
        10485760,    // 10 MiB
        104857600    // 100 MiB
    };

    std::vector<lab4::BenchmarkResult> all_results;

    for (const auto& algo : algos) {
        for (size_t size : sizes) {
            auto result = lab4::benchmark_hash(algo, size, iterations, warmup_secs);
            all_results.push_back(result);
            if (verbose) {
                lab4::print_result(result);
            }
        }
    }

    lab4::print_comparison_table(all_results);

    std::cout << "\nBenchmark complete.\n";
    return 0;
}

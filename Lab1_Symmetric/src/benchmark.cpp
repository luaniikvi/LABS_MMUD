// benchmark.cpp — AES Symmetric Engine Performance Benchmarking
// Multi-threaded: use --threads <N> to scale across cores.
// Lab 1 requirements:
//   • Payload sizes: 1 KB, 4 KB, 16 KB, 256 KB, 1 MB, 8 MB
//   • Warm-up: runs for at least 1 second before timing
//   • Measurement: 30+ independent timed runs of 1000 operations per block
//   • Reports: mean, median, stddev, 95% CI (ms/op) + throughput (MB/s)
//   • All 8 AES modes: ecb, cbc, ctr, ofb, cfb, xts, gcm, ccm

#include "crypto_engine.hpp"
#include "utils.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Statistical helpers
// ---------------------------------------------------------------------------

struct Stats {
    double mean_ms;
    double median_ms;
    double stddev_ms;
    double ci95_ms;
    double throughput_mbs; // MB/s  (aggregate across all threads)
};

static Stats compute_stats(const std::vector<double>& times_ms,
                           size_t payload_bytes) {
    if (times_ms.empty()) return {0, 0, 0, 0, 0};

    double sum = std::accumulate(times_ms.begin(), times_ms.end(), 0.0);
    double mean = sum / static_cast<double>(times_ms.size());

    std::vector<double> sorted = times_ms;
    std::sort(sorted.begin(), sorted.end());
    double median = sorted[sorted.size() / 2];

    double var = 0.0;
    for (double t : times_ms)
        var += (t - mean) * (t - mean);
    var /= static_cast<double>(times_ms.size());
    double stddev = std::sqrt(var);

    // 95% CI: mean ± 1.96 * stddev / sqrt(N)
    double ci95 = 1.96 * stddev / std::sqrt(static_cast<double>(times_ms.size()));

    // throughput: payload_bytes / (mean_ms * 1e-3) / 1e6 = MB/s per thread-stream
    // With multi-threading the wall clock per-op is lower, so throughput
    // naturally reflects the aggregate parallel throughput.
    double throughput_mbs = (mean > 0.0)
        ? (static_cast<double>(payload_bytes) / (mean * 1e-3)) / 1e6
        : 0.0;

    return {mean, median, stddev, ci95, throughput_mbs};
}

static void print_stats(const Stats& s, size_t total_ops) {
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "  Mean:       " << s.mean_ms      << " ms/block (" << total_ops << " ops)\n";
    std::cout << "  Median:     " << s.median_ms     << " ms/block\n";
    std::cout << "  Std Dev:    " << s.stddev_ms     << " ms\n";
    std::cout << "  95% CI:     ~" << s.ci95_ms      << " ms\n";
    std::cout << "  Throughput: " << s.throughput_mbs << " MB/s  (aggregate)\n";
}

// ---------------------------------------------------------------------------
// Per-thread worker: runs a chunk of ops inside a measurement block
// ---------------------------------------------------------------------------
// Each thread receives its own CryptoConfig so there is zero shared mutable
// state during encryption.  For nonce-reuse-protected modes (CTR/GCM/CCM)
// each thread is assigned a distinct IV suffix to avoid collisions.

struct WorkerArg {
    CryptoConfig          cfg;        // private copy
    std::vector<uint8_t>  pt;         // private copy of plaintext
    size_t                ops;        // ops this thread must perform
    double                elapsed_ms; // written back by the worker
};

static void worker_func(WorkerArg& arg) {
    using clk = std::chrono::high_resolution_clock;
    auto start = clk::now();
    for (size_t i = 0; i < arg.ops; ++i) {
        std::vector<uint8_t> tag;
        auto ct = EncryptAES(arg.pt, arg.cfg, tag);
        (void)DecryptAES(ct, arg.cfg, tag);
    }
    auto end = clk::now();
    std::chrono::duration<double, std::milli> d = end - start;
    arg.elapsed_ms = d.count();
}

// ---------------------------------------------------------------------------
// Warmup (single-threaded is fine)
// ---------------------------------------------------------------------------

static void warmup(CryptoConfig& cfg, const std::vector<uint8_t>& pt, double warm_secs) {
    using clk = std::chrono::high_resolution_clock;
    auto deadline = clk::now() + std::chrono::duration<double>(warm_secs);
    while (clk::now() < deadline) {
        std::vector<uint8_t> tag;
        auto ct = EncryptAES(pt, cfg, tag);
        (void)DecryptAES(ct, cfg, tag);
    }
}

// ---------------------------------------------------------------------------
// Make a per-thread IV that is guaranteed unique across threads.
// We XOR the last byte with (thread_index & 0xFF).  For GCM/CCM (12-byte IV)
// we XOR byte 11; for others (16-byte IV) byte 15.  The base IV is random,
// so collisions across up to 256 threads are impossible.
// ---------------------------------------------------------------------------

static std::vector<uint8_t> make_thread_iv(const std::vector<uint8_t>& base_iv,
                                            size_t thread_idx) {
    std::vector<uint8_t> iv = base_iv;
    if (!iv.empty()) {
        iv.back() ^= static_cast<uint8_t>(thread_idx & 0xFF);
    }
    return iv;
}

// ---------------------------------------------------------------------------
// Benchmark one (mode, payload_size) combination, optionally multi-threaded
// ---------------------------------------------------------------------------

static Stats benchmark_one(const std::string& mode,
                           size_t payload_bytes,
                           size_t ops_per_block  = 1000,
                           size_t repeats        = 30,
                           double warm_secs      = 1.5,
                           size_t num_threads    = 1) {
    using clk = std::chrono::high_resolution_clock;

    // Build base config
    CryptoConfig base_cfg;
    base_cfg.mode     = mode;
    base_cfg.allowEcb = true;
    base_cfg.suppressWarnings = true;

    if (mode == "xts") {
        base_cfg.key = GenerateRandomBytes(64);
        base_cfg.iv  = GenerateRandomBytes(16);
    } else if (mode == "gcm" || mode == "ccm") {
        base_cfg.key    = GenerateRandomBytes(32);
        base_cfg.iv     = GenerateRandomBytes(12);
        base_cfg.isAead = true;
    } else {
        base_cfg.key = GenerateRandomBytes(32);
        base_cfg.iv  = (mode == "ecb")
                        ? std::vector<uint8_t>{}
                        : GenerateRandomBytes(16);
    }

    // Payload alignment
    size_t actual_bytes = payload_bytes;
    if (mode == "xts" && actual_bytes % 16 != 0)
        actual_bytes = ((actual_bytes / 16) + 1) * 16;
    if (mode == "ecb") {
        if (actual_bytes > 16384) actual_bytes = 16384;
        if (actual_bytes % 16 != 0)
            actual_bytes = ((actual_bytes / 16) + 1) * 16;
    }

    std::vector<uint8_t> pt = GenerateRandomBytes(actual_bytes);

    // Warm-up (single-threaded)
    warmup(base_cfg, pt, warm_secs);

    // Distribute ops across threads
    size_t effective_threads = std::min(num_threads, ops_per_block);
    if (effective_threads < 1) effective_threads = 1;

    size_t ops_per_thread = ops_per_block / effective_threads;
    size_t remainder_ops  = ops_per_block % effective_threads;

    // total ops actually executed (accounts for rounding)
    size_t total_ops = ops_per_thread * effective_threads + remainder_ops;

    // Measurement phase
    std::vector<double> timings;
    timings.reserve(repeats);

    for (size_t r = 0; r < repeats; ++r) {
        // Build per-thread args (each gets private cfg + pt copy)
        std::vector<WorkerArg> args(effective_threads);
        for (size_t t = 0; t < effective_threads; ++t) {
            args[t].cfg = base_cfg;
            args[t].pt  = pt;
            args[t].ops = ops_per_thread + (t < remainder_ops ? 1 : 0);
            // Unique IV per thread for nonce-protected modes
            if (!base_cfg.iv.empty()) {
                args[t].cfg.iv = make_thread_iv(base_cfg.iv, t);
            }
        }

        // Launch all threads
        auto wall_start = clk::now();
        std::vector<std::thread> threads;
        threads.reserve(effective_threads);
        for (size_t t = 0; t < effective_threads; ++t) {
            threads.emplace_back(worker_func, std::ref(args[t]));
        }
        for (auto& th : threads) th.join();
        auto wall_end = clk::now();

        std::chrono::duration<double, std::milli> wall_elapsed = wall_end - wall_start;

        // ms per op = wall_time / total_ops
        timings.push_back(wall_elapsed.count() / static_cast<double>(total_ops));
    }

    return compute_stats(timings, actual_bytes);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    // CLI defaults
    std::string single_mode = "";
    size_t single_size   = 0;
    size_t ops           = 1000;
    size_t repeats       = 30;
    double warm_secs     = 1.5;
    size_t num_threads   = 1;

    // --help
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") {
            std::cout << "Usage: aestool_bench [options]\n\n";
            std::cout << "AES Symmetric Encryption Performance Benchmark (multi-threaded)\n\n";
            std::cout << "Options:\n";
            std::cout << "  --mode <mode>       Single mode (ecb|cbc|ctr|ofb|cfb|xts|gcm|ccm)\n";
            std::cout << "  --size <bytes>      Single payload size\n";
            std::cout << "  --ops <count>       Ops per measurement block (default: 1000)\n";
            std::cout << "  --repeats <count>   Number of timed runs     (default: 30)\n";
            std::cout << "  --warm <seconds>    Warm-up duration         (default: 1.5)\n";
            std::cout << "  --threads <N>       Worker threads           (default: 1)\n";
            std::cout << "                      Set to 0 to auto-detect ("
                      << std::thread::hardware_concurrency() << " detected)\n";
            std::cout << "  --help, -h          Show this help message\n";
            std::cout << "\nPayload Sizes (all modes by default):\n";
            std::cout << "  1 KB, 4 KB, 16 KB, 256 KB, 1 MB, 8 MB\n";
            std::cout << "\nExamples:\n";
            std::cout << "  aestool_bench --mode cbc --size 1048576 --threads 8\n";
            std::cout << "  aestool_bench --threads 0   # auto-detect CPU count\n";
            return 0;
        }
    }

    // Parse flags
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--mode"    && i+1 < argc) single_mode = argv[++i];
        else if (a == "--size"    && i+1 < argc) single_size = std::stoul(argv[++i]);
        else if (a == "--ops"     && i+1 < argc) ops         = std::stoul(argv[++i]);
        else if (a == "--repeats" && i+1 < argc) repeats     = std::stoul(argv[++i]);
        else if (a == "--warm"    && i+1 < argc) warm_secs   = std::stod(argv[++i]);
        else if (a == "--threads" && i+1 < argc) num_threads = std::stoul(argv[++i]);
    }

    // Auto-detect thread count when user passes --threads 0
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads < 1) num_threads = 4; // fallback
    }

    // Payload sizes per Lab 1 spec
    const std::vector<std::pair<std::string, size_t>> payload_sizes = {
        {"1 KB",   1024},
        {"4 KB",   4096},
        {"16 KB",  16384},
        {"256 KB", 262144},
        {"1 MB",   1048576},
        {"8 MB",   8388608},
    };

    const std::vector<std::string> modes = {
        "ecb", "cbc", "ctr", "ofb", "cfb", "xts", "gcm", "ccm"
    };

    std::cout << "=================================================================\n";
    std::cout << "  AES Benchmark - Lab 1 Symmetric Encryption Engine\n";
    std::cout << "  ops/block=" << ops
              << "  repeats=" << repeats
              << "  warm-up=" << warm_secs << "s"
              << "  threads=" << num_threads << "\n";
    std::cout << "=================================================================\n\n";
    std::cout.flush();

    // What to run
    std::vector<std::string> run_modes =
        single_mode.empty() ? modes
                            : std::vector<std::string>{single_mode};

    std::vector<std::pair<std::string, size_t>> run_sizes;
    if (single_size == 0) {
        run_sizes = payload_sizes;
    } else {
        run_sizes = {{"custom", single_size}};
    }

    // Summary table header
    std::cout << std::left  << std::setw(8)  << "Mode"
              << std::setw(10) << "Payload"
              << std::setw(14) << "Mean(ms/op)"
              << std::setw(14) << "Median(ms)"
              << std::setw(13) << "Stddev(ms)"
              << std::setw(13) << "95%CI(ms)"
              << std::setw(16) << "Throughput(MB/s)"
              << "\n";
    std::cout << std::string(88, '-') << "\n";
    std::cout.flush();

    for (const auto& mode : run_modes) {
        for (const auto& [label, sz] : run_sizes) {
            if (mode == "ecb" && sz > 16384) {
                std::cout << std::left << std::setw(8) << mode
                          << std::setw(10) << label
                          << "  [SKIPPED - ECB limited to 16 KB by design]\n";
                std::cout.flush();
                continue;
            }

            Stats s;
            try {
                s = benchmark_one(mode, sz, ops, repeats, warm_secs, num_threads);
            } catch (const std::exception& e) {
                std::cout << std::left << std::setw(8) << mode
                          << std::setw(10) << label
                          << "  [ERROR: " << e.what() << "]\n";
                std::cout.flush();
                continue;
            }

            std::cout << std::fixed << std::setprecision(4)
                      << std::left  << std::setw(8)  << mode
                      << std::setw(10) << label
                      << std::setw(14) << s.mean_ms
                      << std::setw(14) << s.median_ms
                      << std::setw(13) << s.stddev_ms
                      << std::setw(13) << s.ci95_ms
                      << std::setw(16) << s.throughput_mbs
                      << "\n";
            std::cout.flush();
        }
        std::cout << "\n";
        std::cout.flush();
    }
    std::cout << "Completed.\n";

    // Verbose per-mode breakdown
    if (!single_mode.empty()) {
        std::cout << "\n--- Detailed breakdown for mode: "
                  << single_mode << " (" << num_threads << " threads) ---\n";
        for (const auto& [label, sz] : run_sizes) {
            if (single_mode == "ecb" && sz > 16384) continue;
            try {
                Stats s = benchmark_one(single_mode, sz, ops, repeats,
                                        warm_secs, num_threads);
                std::cout << "\nPayload: " << label
                          << " (" << sz << " bytes)\n";
                print_stats(s, ops);
            } catch (const std::exception& e) {
                std::cout << "\nPayload: " << label
                          << " -> ERROR: " << e.what() << "\n";
            }
        }
    }

    std::cout << "\n=================================================================\n";
    std::cout << "  Benchmark complete.\n";
    std::cout << "=================================================================\n";
    return 0;
}

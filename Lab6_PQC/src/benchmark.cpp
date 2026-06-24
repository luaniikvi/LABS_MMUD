#include "benchmark.hpp"
#include "pq_engine.hpp"
#include "utils.hpp"
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

using namespace lab6;

namespace lab6 {
namespace benchmark {

// ============================================================================
// Temp dir guard for benchmark temp files
// ============================================================================
struct TempDirGuard {
    fs::path dir;
    TempDirGuard() {
        fs::path tmp = fs::temp_directory_path();
        for (int i = 0; i < 100; i++) {
            fs::path p = tmp / ("lab6_bm_" + std::to_string(i));
            if (fs::create_directory(p)) { dir = p; return; }
        }
        dir = tmp / "lab6_bm_fallback";
        fs::create_directories(dir);
    }
    ~TempDirGuard() { if (!dir.empty()) { std::error_code ec; fs::remove_all(dir, ec); } }
    std::string file(const std::string& name) const { return (dir / name).string(); }
};

// ============================================================================
// Statistical helpers
// ============================================================================

double calculate_mean(const std::vector<double>& data) {
    return std::accumulate(data.begin(), data.end(), 0.0) / data.size();
}

double calculate_median(std::vector<double> data) {
    std::sort(data.begin(), data.end());
    size_t n = data.size();
    if (n % 2 == 0) return (data[n/2 - 1] + data[n/2]) / 2.0;
    return data[n/2];
}

double calculate_std_dev(const std::vector<double>& data, double mean) {
    double sq = 0.0;
    for (double v : data) sq += (v - mean) * (v - mean);
    return std::sqrt(sq / data.size());
}

double calculate_ci95(const std::vector<double>& data, double mean) {
    return 1.96 * (calculate_std_dev(data, mean) / std::sqrt(data.size()));
}

void warmup(double seconds) {
    auto start = std::chrono::high_resolution_clock::now();
    while (std::chrono::high_resolution_clock::now() - start < std::chrono::duration<double>(seconds)) {
        volatile int x = 0;
        for (int i = 0; i < 100000; i++) x += i;
    }
}

static std::vector<uint8_t> make_msg(size_t size) {
    std::vector<uint8_t> msg(size);
    for (size_t i = 0; i < size; i++) msg[i] = static_cast<uint8_t>(i & 0xFF);
    return msg;
}

// ============================================================================
// ML-DSA Benchmark
// ============================================================================

MLDSABenchResult benchmark_mldsa(const std::string& curve_name, int num_runs) {
    auto algo = pq_engine::parse_algo(curve_name);
    auto hash = pq_engine::HashAlgo::SHA256;
    auto msg = make_msg(1024);

    std::cout << "\n[BM] " << pq_engine::algo_name(algo) << " Benchmark (" << num_runs << " runs)..." << std::endl;
    warmup();

    MLDSABenchResult result;
    TempDirGuard tmp;

    // Keygen
    {
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto pub = tmp.file("k_pub.pem"), priv = tmp.file("k_priv.pem");
            auto start = std::chrono::high_resolution_clock::now();
            pq_engine::generate_keypair(algo, pub, priv);
            auto end = std::chrono::high_resolution_clock::now();
            times.push_back(std::chrono::duration<double, std::milli>(end - start).count());
            if (i % 10 == 0) std::cout << "\r[BM] Keygen " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.keygen = {calculate_mean(times), calculate_median(times), calculate_std_dev(times, calculate_mean(times)),
                         calculate_ci95(times, calculate_mean(times)), 1000.0 / calculate_mean(times), num_runs};
    }

    // Sign + Verify
    auto pub_f = tmp.file("s_pub.pem"), priv_f = tmp.file("s_priv.pem");
    pq_engine::generate_keypair(algo, pub_f, priv_f);
    void* priv_key = pq_engine::load_private_key(priv_f, algo);
    void* pub_key = pq_engine::load_public_key(pub_f, algo);

    {
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto sig = pq_engine::sign(priv_key, algo, hash, msg);
            auto end = std::chrono::high_resolution_clock::now();
            times.push_back(std::chrono::duration<double, std::milli>(end - start).count());
            if (i % 10 == 0) std::cout << "\r[BM] Sign " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.sign = {calculate_mean(times), calculate_median(times), calculate_std_dev(times, calculate_mean(times)),
                       calculate_ci95(times, calculate_mean(times)), 1000.0 / calculate_mean(times), num_runs};
    }

    {
        auto ref_sig = pq_engine::sign(priv_key, algo, hash, msg);
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            pq_engine::verify(pub_key, algo, hash, msg, ref_sig);
            auto end = std::chrono::high_resolution_clock::now();
            times.push_back(std::chrono::duration<double, std::milli>(end - start).count());
            if (i % 10 == 0) std::cout << "\r[BM] Verify " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.verify = {calculate_mean(times), calculate_median(times), calculate_std_dev(times, calculate_mean(times)),
                         calculate_ci95(times, calculate_mean(times)), 1000.0 / calculate_mean(times), num_runs};
    }

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
    return result;
}

// ============================================================================
// ML-KEM Benchmark
// ============================================================================

MLKEMBenchResult benchmark_mlkem(const std::string& curve_name, int num_runs) {
    auto algo = pq_engine::parse_algo(curve_name);

    std::cout << "\n[BM] " << pq_engine::algo_name(algo) << " Benchmark (" << num_runs << " runs)..." << std::endl;
    warmup();

    MLKEMBenchResult result;
    TempDirGuard tmp;

    // Keygen
    {
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto pub = tmp.file("k_pub.pem"), priv = tmp.file("k_priv.pem");
            auto start = std::chrono::high_resolution_clock::now();
            pq_engine::generate_keypair(algo, pub, priv);
            auto end = std::chrono::high_resolution_clock::now();
            times.push_back(std::chrono::duration<double, std::milli>(end - start).count());
            if (i % 10 == 0) std::cout << "\r[BM] KEM Keygen " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.keygen = {calculate_mean(times), calculate_median(times), calculate_std_dev(times, calculate_mean(times)),
                         calculate_ci95(times, calculate_mean(times)), 1000.0 / calculate_mean(times), num_runs};
    }

    auto pub_f = tmp.file("e_pub.pem"), priv_f = tmp.file("e_priv.pem");
    pq_engine::generate_keypair(algo, pub_f, priv_f);
    void* priv_key = pq_engine::load_private_key(priv_f, algo);
    void* pub_key = pq_engine::load_public_key(pub_f, algo);

    // Encaps
    {
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto [ct, ss] = pq_engine::encapsulate(pub_key, algo);
            auto end = std::chrono::high_resolution_clock::now();
            times.push_back(std::chrono::duration<double, std::milli>(end - start).count());
            if (i % 10 == 0) std::cout << "\r[BM] Encaps " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.encaps = {calculate_mean(times), calculate_median(times), calculate_std_dev(times, calculate_mean(times)),
                         calculate_ci95(times, calculate_mean(times)), 1000.0 / calculate_mean(times), num_runs};
    }

    // Decaps
    {
        auto [ref_ct, ref_ss] = pq_engine::encapsulate(pub_key, algo);
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto ss = pq_engine::decapsulate(priv_key, algo, ref_ct);
            auto end = std::chrono::high_resolution_clock::now();
            times.push_back(std::chrono::duration<double, std::milli>(end - start).count());
            if (i % 10 == 0) std::cout << "\r[BM] Decaps " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.decaps = {calculate_mean(times), calculate_median(times), calculate_std_dev(times, calculate_mean(times)),
                         calculate_ci95(times, calculate_mean(times)), 1000.0 / calculate_mean(times), num_runs};
    }

    pq_engine::free_key(priv_key);
    pq_engine::free_key(pub_key);
    return result;
}

// ============================================================================
// Print helpers
// ============================================================================

void print_result(const std::string& label, const BenchmarkResult& result) {
    std::cout << "\n=== " << label << " ===" << std::endl;
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Runs:        " << result.num_runs << std::endl;
    std::cout << "Mean:        " << result.mean_ms << " ms" << std::endl;
    std::cout << "Median:      " << result.median_ms << " ms" << std::endl;
    std::cout << "Std Dev:     " << result.std_dev_ms << " ms" << std::endl;
    std::cout << "95% CI:      ~" << result.ci95_ms << " ms" << std::endl;
    if (result.throughput_ops > 0)
        std::cout << "Throughput:  " << result.throughput_ops << " ops/s" << std::endl;
}

void print_comparison_table(const std::vector<std::string>& labels,
                           const std::vector<BenchmarkResult>& results) {
    std::cout << "\n=== Comparison Table ===" << std::endl;
    std::cout << std::left << std::setw(35) << "Operation"
              << std::right << std::setw(12) << "Mean (ms)"
              << std::setw(12) << "Median (ms)"
              << std::setw(12) << "Std Dev"
              << std::setw(12) << "95% CI" << std::endl;
    std::cout << std::string(83, '-') << std::endl;
    for (size_t i = 0; i < labels.size(); i++) {
        std::cout << std::left << std::setw(35) << labels[i]
                  << std::right << std::fixed << std::setprecision(3)
                  << std::setw(12) << results[i].mean_ms
                  << std::setw(12) << results[i].median_ms
                  << std::setw(12) << results[i].std_dev_ms
                  << std::setw(12) << results[i].ci95_ms << std::endl;
    }
}

} // namespace benchmark
} // namespace lab6

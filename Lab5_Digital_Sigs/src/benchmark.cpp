#include "benchmark.hpp"
#include "sig_engine.hpp"
#include "utils.hpp"
#include <filesystem>
#include <iostream>
#include <random>

namespace fs = std::filesystem;

using namespace lab5;

namespace lab5 {
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
    return 1.96 * (std_dev / std::sqrt(data.size()));
}

void warmup(double seconds) {
    auto start = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double>(seconds);

    while (std::chrono::high_resolution_clock::now() - start < duration) {
        volatile int x = 0;
        for (int i = 0; i < 100000; i++) x += i;
    }
}

static std::vector<uint8_t> generate_test_message(size_t size) {
    std::vector<uint8_t> msg(size);
    for (size_t i = 0; i < size; i++) {
        msg[i] = static_cast<uint8_t>(i & 0xFF);
    }
    return msg;
}

// Create a unique temp directory and return the path — all temp files go here
static fs::path make_temp_dir() {
    fs::path tmp = fs::temp_directory_path();
    std::string dirname = "lab5_bm_XXXXXX";
    // Use mkstemp-style approach: try random suffixes
    for (int attempt = 0; attempt < 100; attempt++) {
        std::string name = dirname + std::to_string(attempt);
        fs::path p = tmp / name;
        if (fs::create_directory(p)) {
            return p;
        }
    }
    return tmp / "lab5_bm_fallback";
}

// Clean up all temp files created during this benchmark round
struct TempDirGuard {
    fs::path dir;
    TempDirGuard() : dir(make_temp_dir()) {
        fs::create_directories(dir);
    }
    ~TempDirGuard() {
        if (!dir.empty()) {
            std::error_code ec;
            fs::remove_all(dir, ec);
        }
    }
    std::string file(const std::string& name) const {
        return (dir / name).string();
    }
};

ECDSABenchResult benchmark_ecdsa(const std::string& curve_name, int num_runs) {
    auto algo = sig_engine::parse_algo(curve_name);
    auto hash = sig_engine::HashAlgo::SHA256;
    auto msg = generate_test_message(1024); // 1 KiB

    std::cout << "\n[BM] " << sig_engine::algo_name(algo) << " Benchmark (" << num_runs << " runs)..." << std::endl;
    warmup();

    ECDSABenchResult result;
    TempDirGuard tmp;

    // --- Keygen ---
    {
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto pub = tmp.file("key_pub.pem");
            auto priv = tmp.file("key_priv.pem");

            auto start = std::chrono::high_resolution_clock::now();
            sig_engine::generate_keypair(algo, pub, priv);
            auto end = std::chrono::high_resolution_clock::now();

            double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(elapsed);

            if (i % 10 == 0) std::cout << "\r[BM] Keygen run " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.keygen.num_runs = num_runs;
        result.keygen.mean_ms = calculate_mean(times);
        result.keygen.median_ms = calculate_median(times);
        result.keygen.std_dev_ms = calculate_std_dev(times, result.keygen.mean_ms);
        result.keygen.ci95_ms = calculate_ci95(times, result.keygen.mean_ms);
        result.keygen.throughput_ops = 1000.0 / result.keygen.mean_ms;
    }

    // --- Sign & Verify ---
    auto pub_file = tmp.file("sig_pub.pem");
    auto priv_file = tmp.file("sig_priv.pem");
    sig_engine::generate_keypair(algo, pub_file, priv_file);

    void* priv_key = sig_engine::load_private_key(priv_file, algo);
    void* pub_key = sig_engine::load_public_key(pub_file, algo);

    // Sign
    {
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto sig = sig_engine::sign(priv_key, algo, hash, msg);
            auto end = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(elapsed);
            if (i % 10 == 0) std::cout << "\r[BM] Sign run " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.sign.num_runs = num_runs;
        result.sign.mean_ms = calculate_mean(times);
        result.sign.median_ms = calculate_median(times);
        result.sign.std_dev_ms = calculate_std_dev(times, result.sign.mean_ms);
        result.sign.ci95_ms = calculate_ci95(times, result.sign.mean_ms);
        result.sign.throughput_ops = 1000.0 / result.sign.mean_ms;
    }

    // Verify
    {
        auto ref_sig = sig_engine::sign(priv_key, algo, hash, msg);
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            sig_engine::verify(pub_key, algo, hash, msg, ref_sig);
            auto end = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(elapsed);
            if (i % 10 == 0) std::cout << "\r[BM] Verify run " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.verify.num_runs = num_runs;
        result.verify.mean_ms = calculate_mean(times);
        result.verify.median_ms = calculate_median(times);
        result.verify.std_dev_ms = calculate_std_dev(times, result.verify.mean_ms);
        result.verify.ci95_ms = calculate_ci95(times, result.verify.mean_ms);
        result.verify.throughput_ops = 1000.0 / result.verify.mean_ms;
    }

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);

    return result;
}

RSAPSSBenchResult benchmark_rsa_pss(int /*bits*/, int num_runs) {
    auto algo = sig_engine::SigAlgo::RSA_PSS_3072;
    auto hash = sig_engine::HashAlgo::SHA256;
    auto msg = generate_test_message(1024); // 1 KiB

    std::cout << "\n[BM] " << sig_engine::algo_name(algo) << " Benchmark (" << num_runs << " runs)..." << std::endl;
    warmup();

    RSAPSSBenchResult result;
    TempDirGuard tmp;

    // --- Keygen ---
    {
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto pub = tmp.file("rsa_key_pub.pem");
            auto priv = tmp.file("rsa_key_priv.pem");

            auto start = std::chrono::high_resolution_clock::now();
            sig_engine::generate_keypair(algo, pub, priv);
            auto end = std::chrono::high_resolution_clock::now();

            double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(elapsed);

            if (i % 5 == 0) std::cout << "\r[BM] RSA Keygen run " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.keygen.num_runs = num_runs;
        result.keygen.mean_ms = calculate_mean(times);
        result.keygen.median_ms = calculate_median(times);
        result.keygen.std_dev_ms = calculate_std_dev(times, result.keygen.mean_ms);
        result.keygen.ci95_ms = calculate_ci95(times, result.keygen.mean_ms);
        result.keygen.throughput_ops = 1000.0 / result.keygen.mean_ms;
    }

    auto pub_file = tmp.file("rsa_sig_pub.pem");
    auto priv_file = tmp.file("rsa_sig_priv.pem");
    sig_engine::generate_keypair(algo, pub_file, priv_file);

    void* priv_key = sig_engine::load_private_key(priv_file, algo);
    void* pub_key = sig_engine::load_public_key(pub_file, algo);

    // Sign
    {
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto sig = sig_engine::sign(priv_key, algo, hash, msg);
            auto end = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(elapsed);
            if (i % 10 == 0) std::cout << "\r[BM] RSA Sign run " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.sign.num_runs = num_runs;
        result.sign.mean_ms = calculate_mean(times);
        result.sign.median_ms = calculate_median(times);
        result.sign.std_dev_ms = calculate_std_dev(times, result.sign.mean_ms);
        result.sign.ci95_ms = calculate_ci95(times, result.sign.mean_ms);
        result.sign.throughput_ops = 1000.0 / result.sign.mean_ms;
    }

    // Verify
    {
        auto ref_sig = sig_engine::sign(priv_key, algo, hash, msg);
        std::vector<double> times;
        for (int i = 0; i < num_runs; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            sig_engine::verify(pub_key, algo, hash, msg, ref_sig);
            auto end = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
            times.push_back(elapsed);
            if (i % 10 == 0) std::cout << "\r[BM] RSA Verify run " << (i+1) << "/" << num_runs << std::flush;
        }
        std::cout << std::endl;
        result.verify.num_runs = num_runs;
        result.verify.mean_ms = calculate_mean(times);
        result.verify.median_ms = calculate_median(times);
        result.verify.std_dev_ms = calculate_std_dev(times, result.verify.mean_ms);
        result.verify.ci95_ms = calculate_ci95(times, result.verify.mean_ms);
        result.verify.throughput_ops = 1000.0 / result.verify.mean_ms;
    }

    sig_engine::free_key(priv_key);
    sig_engine::free_key(pub_key);

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
    if (result.throughput_ops > 0) {
        std::cout << "Throughput:  " << result.throughput_ops << " ops/s" << std::endl;
    }
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
} // namespace lab5

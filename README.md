# Cryptography & Applications — Laboratory Series (Labs 1–6)

This repository contains the comprehensive implementations for Labs 1–6.

## Labs Implemented

- **Lab 1**: Symmetric Encryption with Crypto++ (AES modes: ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM)
- **Lab 3**: RSA-OAEP & Hybrid Encryption (RSA-3072/4096 + AES-256-GCM envelope encryption)

## Dependencies

| Dependency   | Version     | Purpose                          |
|--------------|-------------|----------------------------------|
| C++17        | C++17+      | Core language                    |
| CMake        | 3.15+       | Build system                     |
| Crypto++     | 8.9+        | Symmetric & asymmetric crypto    |
| Catch2       | 3.x (amalgamated) | Unit testing framework     |
| nlohmann/json| 3.11+       | JSON parsing (header-only)       |

## Installation

### Windows

1. Install [Visual Studio 2022](https://visualstudio.microsoft.com/) with "Desktop development with C++" workload
2. Install [CMake](https://cmake.org/download/) 3.15+ and add to PATH
3. (Optional) Install [MSYS2](https://www.msys2.org/) for MinGW builds

### Linux (Ubuntu LTS)

```bash
sudo apt update
sudo apt install build-essential cmake git
```

## Build Instructions

This project enforces out-of-source builds.

### Windows (MSVC)

```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Windows (MinGW/MSYS2)

Open MSYS2 MinGW64 terminal:

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

### Linux (Ubuntu LTS)

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## CLI Usage

### Lab 1 — aestool (Symmetric Encryption)

```bash
# Encrypt with AES-256-GCM
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin

# Decrypt
aestool decrypt --mode gcm --key key.bin --in ct.bin --out msg.txt

# Run KAT validation
aestool --kat vectors.json
```

### Lab 3 — rsatool (RSA-OAEP & Hybrid)

```bash
# Generate RSA-3072 key pair (PEM + DER + metadata JSON)
rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem

# Encrypt small message (direct RSA-OAEP)
rsatool encrypt --in msg.txt --pub pub.pem --out ct.bin

# Encrypt large file (auto hybrid: RSA-OAEP + AES-256-GCM)
rsatool encrypt --in large.bin --pub pub.pem --out envelope.bin

# Decrypt (auto-detects mode)
rsatool decrypt --in ct.bin --priv priv.pem --out msg.txt

# With OAEP label
rsatool encrypt --text "Hello" --pub pub.pem --out ct.bin --label "MyLabel"

# Run KAT validation
rsatool --kat test_vectors/rsa_oaep_kats.json
```

## Running Tests

After building, run all unit tests using CTest:

For MSVC:
```cmd
cd build
ctest -C Release -V
```
For others:
```bash
cd build
ctest -V
```

Or run individual test executables:

```bash
# Lab 1 tests
./Lab1_Symmetric/test_lab1.exe

# Lab 3 tests
./Lab3_RSA_Hybrid/test_lab3.exe
```

## Running Benchmarks

```bash
# Lab 1 benchmark (AES modes)
./Lab1_Symmetric/benchmark_lab1.exe

# Lab 3 benchmark (RSA + hybrid)
./Lab3_RSA_Hybrid/benchmark_lab3.exe
```

## Known Limitations

- RSA key sizes limited to 3072 and 4096 bits
- PEM format uses simplified Base64 encoding (not full PKCS#8)
- No password-protected private keys
- Single-threaded implementations
- Benchmark results vary by hardware; use fixed CPU governor for reproducibility

## Project Structure

```
Labs/
├── CMakeLists.txt                  # Top-level build configuration
├── README.md                       # This file
├── LABS_requirements.txt           # Lab specification document
├── Lab1_Symmetric/                 # Lab 1: AES symmetric encryption
│   ├── CMakeLists.txt
│   ├── src/                        # Source code
│   ├── include/                    # Catch2, nlohmann/json, dll_export
│   └── SampleData/                 # Test vectors
├── Lab3_RSA_Hybrid/                # Lab 3: RSA-OAEP & hybrid encryption
│   ├── CMakeLists.txt
│   ├── src/                        # Source code
│   ├── include/                    # Catch2, nlohmann/json, dll_export
│   └── test_vectors/               # KAT JSON vectors
└── external/
    ├── cryptopp/                   # Crypto++ library (headers + libs)
    └── openssl/                    # Openssl library (headers + libs)
```

## Academic Integrity

This implementation is for educational purposes only. All cryptographic operations use established libraries (Crypto++) and follow NIST standards. Test keys included in the repository are for testing only and must never be used in production.

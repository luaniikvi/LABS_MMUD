# Lab 4 — Hashing, PKI, and Practical Attacks

A comprehensive C++ CLI tool and Python GUI for cryptographic hashing, X.509 certificate analysis, and practical attack demonstrations.

## Features

- **Hash Suite**: SHA-2 (224/256/384/512), SHA-3 (224/256/384/512), SHAKE (128/256), MD5
- **HMAC**: SHA-224/256/384/512
- **Streaming Mode**: Memory-efficient hashing for multi-GB files
- **X.509 Certificate Analysis**: Parse PEM certificates, extract fields, verify signatures
- **Length-Extension Attack Demo**: Demonstrate vulnerability of naive `H(key||message)` MAC
- **MD5 Collision Demo**: Pre-computed collision pair showing MD5 is broken
- **Performance Benchmarking**: Statistical benchmarking with mean, median, stddev, CI95
- **Known Answer Tests (KATs)**: NIST FIPS 180-4, FIPS 202, RFC 1321, RFC 4231
- **TLS Deployment Configs**: Nginx/Apache ECDSA TLS 1.2/1.3 configurations

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| Crypto++ | 8.9+ | SHA-2, SHA-3, SHAKE, MD5, HMAC |
| OpenSSL | 3.0+ | X.509 certificate parsing |
| nlohmann/json | 3.11+ | JSON parsing (KAT vectors) |
| Catch2 | v3 (local) | Unit testing |

## Build

### Windows (MSVC)
```bash
cd Lab4_Hash_PKI
mkdir build && cd build
cmake .. -G "Visual Studio 18 2026"
cmake --build . --config Release
```

### Windows (MinGW/MSYS2)
```bash
cd Lab4_Hash_PKI
mkdir build && cd build
cmake .. -G "MinGW Makefiles"
cmake --build .
```

### Linux
```bash
cd Lab4_Hash_PKI
mkdir build && cd build
cmake ..
cmake --build .
```

### Build All Labs (from root)
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## CLI Usage

### Hash a file
```bash
hashtool hash --algo sha256 --in file.bin
hashtool hash --algo sha3-512 --in large.iso --stream
hashtool hash --algo sha256 --text "Hello World"
hashtool hash --algo sha512 --in file.bin --out digest.hex --encode hex
```

### Compute HMAC
```bash
hashtool hmac --algo sha256 --key-hex AABB --text "message"
hashtool hmac --algo sha512 --key keyfile.bin --in data.bin
```

### SHAKE (variable output)
```bash
hashtool shake --algo shake128 --text "test" --outlen 64
hashtool shake --algo shake256 --in file.bin --outlen 128
```

### X.509 Certificate Inspection
```bash
hashtool x509 --cert server.pem
hashtool x509 --cert server.pem --issuer-key ca.pem
```

### MD5 Collision Demo
```bash
hashtool md5-demo --dir demo/md5_collision
```

### Length-Extension Attack
```bash
hashtool length-ext --mac 79054025255fb1a2... --key-len 14 --msg-len 5 --append "&admin=1"
```

### Run KAT Tests
```bash
hashtool --kat test_vectors/sha2_kats.json
hashtool --kat test_vectors/sha3_kats.json
hashtool --kat test_vectors/md5_kats.json
```

### Run Benchmarks
```bash
benchmark --iterations 30 --verbose
```

### Run Catch2 Tests
```bash
catch2_test --reporter console
ctest --output-on-failure
```

## Supported Algorithms

| Algorithm | Type | Output Size |
|-----------|------|-------------|
| SHA-224 | SHA-2 | 28 bytes |
| SHA-256 | SHA-2 | 32 bytes |
| SHA-384 | SHA-2 | 48 bytes |
| SHA-512 | SHA-2 | 64 bytes |
| SHA3-224 | SHA-3 | 28 bytes |
| SHA3-256 | SHA-3 | 32 bytes |
| SHA3-384 | SHA-3 | 48 bytes |
| SHA3-512 | SHA-3 | 64 bytes |
| SHAKE128 | XOF | Variable |
| SHAKE256 | XOF | Variable |
| MD5 | Legacy | 16 bytes |

## GUI

Run the PyQt6 GUI:
```bash
python gui_qt6.py
```

Tabs: Hash, HMAC, SHAKE, X.509 Inspector, MD5 Collision Demo, Length-Extension Attack, Benchmark, Catch2 Tests, KAT Tests.

## Project Structure

```
Lab4_Hash_PKI/
├── include/           # Catch2, nlohmann/json, dll_export.hpp
├── src/
│   ├── main.cpp           # CLI entry point
│   ├── hash_engine.cpp    # SHA-2/3/SHAKE/MD5 via Crypto++
│   ├── x509_parser.cpp    # X.509 via OpenSSL
│   ├── length_ext.cpp     # Self-contained SHA-256 length-extension
│   ├── utils.cpp          # Hex, base64, file I/O
│   ├── tests.cpp          # Catch2 tests + KATs
│   ├── benchmark.cpp      # Performance benchmarks
│   ├── benchmark_main.cpp # Benchmark CLI
│   └── dll_wrapper.cpp    # DLL exports for GUI
├── test_vectors/          # NIST/RFC KAT JSON files
├── demo/
│   ├── md5_collision/     # Pre-computed MD5 collision pair
│   └── tls/              # Nginx/Apache ECDSA TLS configs
├── CMakeLists.txt
├── gui_qt6.py            # PyQt6 GUI
└── README.md
```

## Known Limitations

- X.509 parsing requires OpenSSL to be available at build time
- MD5 collision demo uses a fixed collision pair (Wang et al. 2004)
- Length-extension attack only supports SHA-256 (SHA-2 family)
- TLS configs are templates; actual deployment requires OS-specific setup
- Streaming SHAKE requires full file to be available (no true streaming for XOF)

# CryptoLab5 — Classical Digital Signatures CLI (ECDSA, RSA-PSS)

## Overview

CryptoLab5 is a command-line digital signature tool implemented in C++17 using OpenSSL and Crypto++ libraries. It supports ECDSA P-256 and P-384 signatures with deterministic nonces (RFC 6979), RSA-PSS-3072 probabilistic signatures, PEM and DER key formats, DER/hex/base64 signature encoding, JSON-based Known Answer Tests (KAT), statistical performance benchmarking, and cross-platform builds via CMake.

An optional PyQt6 GUI (`gui_qt6.py`) is provided as a bonus extension, calling the same compiled shared library (`sigtool.dll` / `libsigtool.so`) through `ctypes`.

## Features

* ECDSA P-256 (secp256r1) — deterministic signing via RFC 6979
* ECDSA P-384 (secp384r1) — bonus higher security curve
* RSA-PSS-3072 — probabilistic signature scheme with SHA-256 and 32-byte salt
* PEM and DER key format support (auto-generated)
* Signature encoding: DER, hex, base64
* NIST KAT (Known Answer Test) runner (`--kat`)
* Statistical performance benchmarking
* Catch2 unit tests with per-test PASS/FAIL output
* Cross-platform build support (MSVC, MinGW64, GCC/Linux)
* Out-of-source CMake builds enforced
* Optional PyQt6 GUI bonus

---

## Dependencies

| Dependency   | Version               |
|--------------|-----------------------|
| C++ Standard | C++17                 |
| CMake        | 3.15 or newer         |
| Crypto++     | 8.9                   |
| OpenSSL      | 4.0.0                 |
| GCC (Ubuntu) | 9+ recommended        |
| MSVC         | Visual Studio 18 2026 |
| PyQt6        | (optional, for GUI)   |

### External Dependency Layout

Crypto++ and OpenSSL must be pre-installed under:

```text
external/
├── cryptopp/
│   ├── include/
│   └── lib/
│       ├── libcryptopp.a   (MSYS2 / Linux)
│       └── cryptopp.lib    (MSVC)
└── openssl/
    ├── include/
    └── lib64/
        ├── libcrypto.a     (MSYS2 / Linux)
        ├── libssl.a
        ├── libcrypto_static.lib (MSVC)
        └── libssl_static.lib    (MSVC)
```

---

## Build Commands

### Linux (Ubuntu LTS)

```bash
cd Lab5_Digital_Sigs
mkdir build && cd build
cmake ..
cmake --build .
```

Executables: `build/sigtool`, `build/catch2_test`, `build/benchmark`, `build/libsigtool.so`

### Windows (MSVC)

```cmd
cd Lab5_Digital_Sigs
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

Executables: `build\Release\sigtool.exe`, `build\Release\catch2_test.exe`, `build\Release\benchmark.exe`, `build\Release\sigtool.dll`

### Windows (MSYS2 / MinGW64)

```cmd
cd Lab5_Digital_Sigs
mkdir build
cd build
cmake ..
cmake --build .
```

Executables: `build\sigtool.exe`, `build\catch2_test.exe`, `build\benchmark.exe`, `build\sigtool.dll`

### Build Targets

| Target        | Description                                       |
|---------------|---------------------------------------------------|
| `sigtool`     | Main CLI digital signature tool                   |
| `sigtool_lib` | Shared library (`sigtool.dll` / `.so`) for GUI    |
| `catch2_test` | Catch2 unit test executable                       |
| `benchmark`   | Performance benchmark                             |

---

## CLI Reference

```text
sigtool <command> [options]

COMMANDS:
  keygen              Generate signature key pair
  sign                Create a detached digital signature
  verify              Verify a detached digital signature

OPTIONS:
  --algo <algo>       Algorithm: ecdsa-p256 (default), ecdsa-p384, rsa-pss-3072
  --hash <hash>       Hash: sha256 (default), sha384
  --pub <file>        Public key file (PEM format)
  --priv <file>       Private key file (PEM format)
  --pub-der <file>    Public key output in DER format
  --priv-der <file>   Private key output in DER format
  --in <file>         Input file path (binary-safe)
  --text "..."        Direct UTF-8 text input
  --out <file>        Output signature file
  --sig <file>        Signature file (for verify)
  --encode <type>     Signature encoding: der (default), hex, base64
  --kat <file.json>   Run Known Answer Tests from JSON vector file
  --threads <N>       Number of threads (default: 1)
  --verbose           Enable detailed processing telemetry
```

---

## Example CLI Usage

### Show Help

```bash
sigtool --help
```

### Generate ECDSA P-256 Key Pair

```bash
sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem
```

### Generate RSA-PSS-3072 Key Pair

```bash
sigtool keygen --algo rsa-pss-3072 --pub pub.pem --priv priv.pem
```

### Sign a Message

```bash
sigtool sign --algo ecdsa-p256 --text "Hello, Digital Signatures!" --out sig.der --priv priv.pem
```

### Sign a File

```bash
sigtool sign --algo ecdsa-p256 --in msg.bin --out sig.der --priv priv.pem
```

### Verify a Signature

```bash
sigtool verify --algo ecdsa-p256 --text "Hello, Digital Signatures!" --sig sig.der --pub pub.pem
```

### Verify with File

```bash
sigtool verify --algo rsa-pss-3072 --in msg.bin --sig sig.der --pub pub.pem
```

### Hex-Encoded Signature Output

```bash
sigtool sign --algo ecdsa-p256 --text "test" --out sig.hex --priv priv.pem --encode hex
```

### Run KAT Tests

```bash
sigtool --kat test_vectors/sig_kats.json
```

### ECDSA P-384 Signing

```bash
sigtool keygen --algo ecdsa-p384 --pub pub.pem --priv priv.pem
sigtool sign --algo ecdsa-p384 --text "High security message" --out sig.der --priv priv.pem
sigtool verify --algo ecdsa-p384 --text "High security message" --sig sig.der --pub pub.pem
```

---

## Performance Benchmark

The `benchmark` executable provides statistical benchmarking for ECDSA and RSA-PSS signing and verification.

### Usage

```bash
benchmark [--threads N] [--iterations N] [--warm SECS] [--verbose]
```

### Methodology

Per the lab performance protocol:

1. **Warm-up**: 1–2 seconds to stabilize caches
2. **Runs**: 30+ independent timed runs
3. **Statistics reported**: Mean, Median, Standard Deviation, 95% Confidence Interval, Throughput (ops/s)

### Benchmarked Operations

* ECDSA P-256 key generation, sign, verify
* ECDSA P-384 key generation, sign, verify
* RSA-PSS-3072 key generation, sign, verify

### Signature Sizes

| Algorithm | Signature Size |
|-----------|---------------|
| ECDSA P-256 | ~70–72 bytes (DER) |
| ECDSA P-384 | ~102–104 bytes (DER) |
| RSA-PSS-3072 | 384 bytes (raw) |

### Multi-threading

Use `--threads N` to scale across CPU cores. Set to `0` for auto-detection.

---

## Unit Tests

Unit tests use [Catch2 v3](https://github.com/catchorg/Catch2) via local amalgamation (headers and source in `include/catch2/`).

### Test Coverage

| Category | Tests |
|----------|-------|
| **Algorithm Parsing** | Valid and invalid algorithm/hash strings |
| **ECDSA P-256 Keygen** | Valid key generation, key size check |
| **ECDSA P-256 Sign/Verify** | Small message, empty message, large message (1 MiB) |
| **ECDSA P-256 Negative** | Wrong key fails, modified message fails, modified signature fails, wrong hash fails |
| **RSA-PSS-3072 Keygen** | Valid key generation, key size check |
| **RSA-PSS-3072 Sign/Verify** | Small message, empty message |
| **RSA-PSS-3072 Negative** | Wrong key fails, modified message fails, modified signature fails |
| **Batch Verify** | 10 signatures verified in sequence |
| **DER Format** | Public/private key DER roundtrip |
| **Encoding** | Hex and Base64 roundtrip |

---

## Project Structure

```text
Lab5_Digital_Sigs/
├── CMakeLists.txt              ← Build system (all targets)
├── gui_qt6.py                  ← Optional PyQt6 GUI (bonus)
├── include/
│   ├── catch2/
│   │   ├── catch_amalgamated.hpp
│   │   └── catch_amalgamated.cpp
│   ├── nlohmann/
│   │   └── json.hpp
│   └── dll_export.hpp          ← DLL export macros
├── src/
│   ├── main.cpp                ← CLI entry point (sigtool)
│   ├── sig_engine.cpp          ← ECDSA + RSA-PSS implementation
│   ├── sig_engine.hpp
│   ├── utils.cpp               ← Hex/Base64/file I/O/SHA hashing/KAT runner
│   ├── utils.hpp
│   ├── dll_wrapper.cpp         ← C exports for shared library (GUI)
│   ├── benchmark.cpp           ← Performance benchmark
│   ├── benchmark.hpp
│   ├── benchmark_main.cpp      ← Benchmark CLI
│   ├── tests.cpp               ← Catch2 unit tests
│   └── applink.c               ← OpenSSL applink (Windows)
├── test_vectors/
│   └── sig_kats.json           ← KAT test vectors
└── build/                      ← Out-of-source build output
```

---

## Known Answer Tests (KAT)

Run the bundled test vectors:

```bash
sigtool --kat test_vectors/sig_kats.json
```

Coverage includes:
* ECDSA P-256 sign/verify with SHA-256
* ECDSA P-384 sign/verify with SHA-384
* RSA-PSS-3072 sign/verify with SHA-256
* Empty messages, large messages (1 MiB)
* Special UTF-8 characters
* Negative tests (expected failure)

---

## Security Discussion

### Deterministic ECDSA Nonces (RFC 6979)

ECDSA signing uses deterministic nonces via OpenSSL's RFC 6979 implementation. This eliminates the catastrophic nonce reuse vulnerability that affected many real-world implementations (e.g., Sony PlayStation 3 ECDSA key recovery).

### RSA-PSS vs PKCS#1 v1.5

RSA-PSS provides a provably secure (IND-CCA2) signature scheme with randomized salt per signature, unlike the older PKCS#1 v1.5 scheme which has known vulnerabilities. Each RSA-PSS signature uses a fresh 32-byte random salt.

### Fail-Closed Behavior

All signature verification failures — including modified messages, modified signatures, wrong public keys, wrong hash algorithms, and malformed inputs — result in explicit failure with clear error messages.

---

## Python GUI (Bonus)

The optional GUI is implemented in `gui_qt6.py` using PyQt6 and `ctypes`.

### Requirements

```bash
pip install PyQt6
```

### Running the GUI

```bash
python gui_qt6.py
```

### GUI Tabs

* Key Generation — ECDSA P-256/P-384, RSA-PSS-3072
* Sign — text or file input, optional output
* Verify — text or file input verification
* Tests — Catch2 unit tests (background), KAT validation
* Benchmark — full benchmark suite (background, non-blocking)

---

## Known Limitations

1. RSA key sizes limited to 3072 bits (per lab requirements)
2. ECDSA limited to P-256 and P-384 curves
3. PEM format uses standard SubjectPublicKeyInfo / PKCS#8
4. No support for password-protected private keys
5. Single-threaded implementations
6. Deterministic ECDSA via OpenSSL defaults (OpenSSL 3.x+)
7. RSA-PSS key generation may take 30+ seconds

---

## License

This project is provided for educational and laboratory purposes.

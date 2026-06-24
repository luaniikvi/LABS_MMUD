# CryptoLab6 — Post-Quantum Cryptography CLI (ML-DSA, ML-KEM)

## Overview

CryptoLab6 is a command-line post-quantum cryptography tool implemented in C++17 using OpenSSL 4.0's native PQC (Post-Quantum Cryptography) support and Crypto++. It supports ML-DSA-44 and ML-DSA-65 digital signatures (FIPS 204) and ML-KEM-512 key encapsulation (FIPS 203), PEM and DER key formats, PQ certificate creation and verification, JSON-based Known Answer Tests (KAT), statistical performance benchmarking, and cross-platform builds via CMake.

An optional PyQt6 GUI (`gui_qt6.py`) is provided as a bonus extension, calling the same compiled shared library (`pqtool.dll` / `libpqtool.so`) through `ctypes`.

## Features

* ML-DSA-44 (FIPS 204) — post-quantum digital signatures, ~128-bit security
* ML-DSA-65 (FIPS 204) — higher security PQC signatures, ~192-bit security (bonus)
* ML-KEM-512 (FIPS 203) — post-quantum key encapsulation mechanism
* PEM and DER key format support (auto-generated)
* ML-KEM encapsulation and decapsulation
* PQ Certificate — ML-DSA-signed certificate structure (mini-project)
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

Crypto++ and OpenSSL 4.0 must be pre-installed under:

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
cd Lab6_PQC
mkdir build && cd build
cmake ..
cmake --build .
```

Executables: `build/pqtool`, `build/catch2_test`, `build/benchmark`, `build/libpqtool.so`

### Windows (MSVC)

```cmd
cd Lab6_PQC
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

Executables: `build\Release\pqtool.exe`, `build\Release\catch2_test.exe`, `build\Release\benchmark.exe`, `build\Release\pqtool.dll`

### Windows (MSYS2 / MinGW64)

```cmd
cd Lab6_PQC
mkdir build
cd build
cmake ..
cmake --build .
```

Executables: `build\pqtool.exe`, `build\catch2_test.exe`, `build\benchmark.exe`, `build\pqtool.dll`

### Build Targets

| Target       | Description                                       |
|--------------|---------------------------------------------------|
| `pqtool`     | Main CLI post-quantum crypto tool                 |
| `pqtool_lib` | Shared library (`pqtool.dll` / `.so`) for GUI     |
| `catch2_test`| Catch2 unit test executable                       |
| `benchmark`  | Performance benchmark                             |

---

## CLI Reference

```text
pqtool <command> [options]

COMMANDS:
  keygen              Generate PQC key pair (ML-DSA or ML-KEM)
  sign                Create ML-DSA signature
  verify              Verify ML-DSA signature
  encaps              ML-KEM encapsulation
  decaps              ML-KEM decapsulation
  cert                PQ Certificate operations (sign/verify)

OPTIONS:
  --algo <algo>       Algorithm: mldsa-44 (default), mldsa-65, mlkem-512
  --hash <hash>       Hash: sha256 (default), sha384
  --pub <file>        Public key file (PEM format)
  --priv <file>       Private key file (PEM format)
  --ca-pub <file>     CA public key file (for cert verify)
  --ca-priv <file>    CA private key file (for cert sign)
  --subject <str>     Subject name (for cert)
  --subject-pub <file>Subject public key file (for cert)
  --in <file>         Input file path (binary-safe)
  --text "..."        Direct UTF-8 text input
  --out <file>        Output file
  --sig <file>        Signature file (for verify)
  --ct <file>         Ciphertext file (for decapsulate)
  --ss <file>         Shared secret output file
  --encode <type>     Encoding: der (default), hex, base64
  --kat <file.json>   Run Known Answer Tests from JSON vector file
  --threads <N>       Number of threads (default: 1)
  --verbose           Enable detailed processing telemetry
```

---

## Example CLI Usage

### Show Help

```bash
pqtool --help
```

### Generate ML-DSA-44 Key Pair

```bash
pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem
```

### Generate ML-KEM-512 Key Pair

```bash
pqtool keygen --algo mlkem-512 --pub kem_pub.pem --priv kem_priv.pem
```

### Sign with ML-DSA-44

```bash
pqtool sign --algo mldsa-44 --text "Hello, Post-Quantum World!" --out sig.bin --priv priv.pem
```

### Sign a File

```bash
pqtool sign --algo mldsa-44 --in msg.bin --out sig.bin --priv priv.pem
```

### Verify ML-DSA Signature

```bash
pqtool verify --algo mldsa-44 --text "Hello, Post-Quantum World!" --sig sig.bin --pub pub.pem
```

### ML-KEM Encapsulation

```bash
pqtool encaps --algo mlkem-512 --pub kem_pub.pem --ct ct.bin --ss ss.bin
```

### ML-KEM Decapsulation

```bash
pqtool decaps --algo mlkem-512 --priv kem_priv.pem --ct ct.bin --ss ss_recovered.bin
```

### Create PQ Certificate

```bash
# 1. Generate CA key pair
pqtool keygen --algo mldsa-44 --pub ca_pub.pem --priv ca_priv.pem

# 2. Generate subject key pair
pqtool keygen --algo mldsa-44 --pub sub_pub.pem --priv sub_priv.pem

# 3. Sign subject's public key with CA
pqtool cert --ca-priv ca_priv.pem --subject-pub sub_pub.pem --subject "Alice" --out cert.json
```

### Verify PQ Certificate

```bash
pqtool cert --ca-pub ca_pub.pem --in cert.json
```

### Run KAT Tests

```bash
pqtool --kat test_vectors/pq_kats.json
```

---

## Algorithm Specifications

### ML-DSA (FIPS 204)

| Parameter Set | Security Level | Signature Size | Public Key Size | Private Key Size |
|--------------|---------------|----------------|-----------------|------------------|
| ML-DSA-44    | Level 2 (~128-bit) | ~2,420 bytes | ~1,312 bytes | ~2,560 bytes |
| ML-DSA-65    | Level 3 (~192-bit) | ~3,309 bytes | ~1,952 bytes | ~4,032 bytes |

ML-DSA uses deterministic signing — no nonce reuse risk unlike ECDSA. Signing uses SHAKE internally (no explicit hash parameter needed).

### ML-KEM (FIPS 203)

| Parameter Set | Security Level | Ciphertext Size | Public Key Size | Private Key Size |
|--------------|---------------|-----------------|-----------------|------------------|
| ML-KEM-512   | Level 2 (~128-bit) | ~768 bytes | ~800 bytes | ~1,632 bytes |

ML-KEM provides IND-CCA2 security via the Fujisaki-Okamoto transform.

---

## Performance Benchmark

The `benchmark` executable provides statistical benchmarking for PQC operations.

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

* ML-DSA-44 and ML-DSA-65 key generation, sign, verify
* ML-KEM-512 key generation, encapsulate, decapsulate

---

## Unit Tests

Unit tests use [Catch2 v3](https://github.com/catchorg/Catch2) via local amalgamation (headers and source in `include/catch2/`).

### Test Coverage

| Category | Tests |
|----------|-------|
| **Algorithm Parsing** | Valid and invalid algorithm/hash strings |
| **ML-DSA-44 Keygen** | Valid key generation |
| **ML-DSA-44 Sign/Verify** | Small message, large message (1 MiB), batch verify (10 sigs) |
| **ML-DSA-44 Negative** | Modified message fails, modified signature fails |
| **ML-DSA-65 Sign/Verify** | Small message verification |
| **ML-KEM-512 Keygen** | Valid key generation |
| **ML-KEM-512 Encaps/Decaps** | Roundtrip shared secret match |
| **ML-KEM-512 Negative** | Tampered ciphertext → different shared secret |
| **DER Format** | Public/private key DER roundtrip |
| **PQ Certificate** | Sign/verify certificate, tampered cert fails |
| **Encoding** | Hex and Base64 roundtrip |

---

## PQ Certificate Mini-Project

Post-quantum certificates use a simplified JSON-based structure:

```json
{
  "subject": "Alice",
  "public_key": "<base64 ML-DSA public key>",
  "issuer": "PQ-CA",
  "algorithm": "ML-DSA-44",
  "signature": "<hex ML-DSA signature by CA>"
}
```

The CA signs the `subject + public_key` concatenation. Verification checks that the CA's signature matches the certificate's signed data.

### Certificate Operations

| Operation | Command |
|-----------|---------|
| **Sign** | `pqtool cert --ca-priv ca.pem --subject-pub sub.pem --subject "Alice" --out cert.json` |
| **Verify** | `pqtool cert --ca-pub ca.pem --in cert.json` |

---

## Project Structure

```text
Lab6_PQC/
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
│   ├── main.cpp                ← CLI entry point (pqtool)
│   ├── pq_engine.cpp           ← ML-DSA + ML-KEM via OpenSSL 4.0 EVP API
│   ├── pq_engine.hpp
│   ├── utils.cpp               ← Hex/Base64/file I/O/SHA hashing/KAT runner
│   ├── utils.hpp
│   ├── dll_wrapper.cpp         ← C exports for shared library (GUI)
│   ├── benchmark.cpp           ← Performance benchmark
│   ├── benchmark.hpp
│   ├── benchmark_main.cpp      ← Benchmark CLI
│   ├── tests.cpp               ← Catch2 unit tests
│   └── applink.c               ← OpenSSL applink (Windows)
├── test_vectors/
│   └── pq_kats.json            ← KAT test vectors
└── build/                      ← Out-of-source build output
```

---

## Known Answer Tests (KAT)

Run the bundled test vectors:

```bash
pqtool --kat test_vectors/pq_kats.json
```

Coverage includes:
* ML-DSA-44 sign/verify with various message sizes
* ML-DSA-65 sign/verify
* ML-KEM-512 encaps/decaps roundtrip
* Large messages (1 MiB)
* UTF-8 special characters
* Negative tests (expected failure)

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

* Key Generation — ML-DSA-44/65, ML-KEM-512
* Sign (ML-DSA) — text or file input
* Verify (ML-DSA) — text or file input
* KEM (ML-KEM) — encapsulate and decapsulate
* Certificate — sign and verify PQ certificates
* Tests — Catch2 unit tests (background), KAT validation
* Benchmark — full benchmark suite (background, non-blocking)

---

## Known Limitations

1. ML-KEM limited to ML-KEM-512 (Level 2) parameter set
2. ML-DSA limited to ML-DSA-44 and ML-DSA-65 parameter sets (ML-DSA-87 not supported)
3. PQ Certificate format is a simplified JSON structure (not ASN.1/DER X.509)
4. ML-DSA signature verification timing not constant-time (library limitation)
5. Requires OpenSSL 4.0+ with native PQC algorithm support
6. ML-DSA signatures are 10–30× larger than equivalent ECDSA signatures
7. ML-KEM ciphertexts and keys are larger than RSA equivalents

---

## Security Discussion

### Post-Quantum Security

All algorithms implemented in this lab are based on lattice cryptography (Module-LWE and Module-SIS), which is believed to be secure against both classical and quantum computers.

### ML-DSA Deterministic Signing

Unlike ECDSA, ML-DSA uses deterministic signing natively — there is no nonce to generate, eliminating the catastrophic nonce reuse vulnerability that has affected many ECDSA implementations.

### ML-KEM IND-CCA2 Security

ML-KEM achieves IND-CCA2 security through the Fujisaki-Okamoto transform, which converts a weaker IND-CPA-secure KEM into one that resists adaptive chosen-ciphertext attacks.

### Migration Path

Post-quantum cryptography is designed to coexist with classical algorithms in hybrid deployments. A production system might use ECDSA + ML-DSA dual signatures or ECDHE + ML-KEM hybrid key exchange during the transition period.

---

## License

This project is provided for educational and laboratory purposes.

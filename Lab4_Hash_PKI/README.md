# CryptoLab4 — Hashing, PKI, and Practical Attacks CLI

## Overview

CryptoLab4 is a command-line hashing and PKI analysis tool implemented in C++17 using Crypto++ and OpenSSL libraries. It supports SHA-2, SHA-3, SHAKE, and MD5 hashing algorithms, HMAC, streaming mode for large files, X.509 certificate parsing and signature verification, MD5 collision demonstration, length-extension attack demonstration, JSON-based Known Answer Tests (KAT), statistical performance benchmarking, and cross-platform builds via CMake.

An optional PyQt6 GUI (`gui_qt6.py`) is provided as a bonus extension.

## Features

* SHA-2 family: SHA-224, SHA-256, SHA-384, SHA-512
* SHA-3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512
* SHAKE extendable-output functions (SHAKE128, SHAKE256)
* HMAC with SHA-2 algorithms (224/256/384/512)
* Streaming mode for memory-efficient hashing of multi-GB files
* X.509 certificate parsing (PEM) — subject, issuer, validity, key info, SANs
* X.509 signature verification with issuer public key
* MD5 collision demonstration (pair of files with identical MD5 hash)
* Length-extension attack demonstration on naive `H(key || message)` MAC
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
cd Lab4_Hash_PKI
mkdir build && cd build
cmake ..
cmake --build .
```

Executables: `build/hashtool`, `build/catch2_test`, `build/benchmark`, `build/libhashtool.so`

### Windows (MSVC)

```cmd
cd Lab4_Hash_PKI
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

Executables: `build\Release\hashtool.exe`, `build\Release\catch2_test.exe`, `build\Release\benchmark.exe`, `build\Release\hashtool.dll`

### Windows (MSYS2 / MinGW64)

```cmd
cd Lab4_Hash_PKI
mkdir build
cd build
cmake ..
cmake --build .
```

Executables: `build\hashtool.exe`, `build\catch2_test.exe`, `build\benchmark.exe`, `build\hashtool.dll`

### Build Targets

| Target         | Description                                       |
|----------------|---------------------------------------------------|
| `hashtool`     | Main CLI hashing & PKI analysis tool              |
| `hashtool_lib` | Shared library (`hashtool.dll` / `.so`) for GUI   |
| `catch2_test`  | Catch2 unit test executable                       |
| `benchmark`    | Performance benchmark                             |

---

## CLI Reference

```text
hashtool <command> [options]

COMMANDS:
  hash                Compute hash digest
  hmac                Compute HMAC
  shake               Compute SHAKE extendable output
  x509                Parse and verify X.509 certificate
  md5-demo            Demonstrate MD5 collision
  length-ext          Perform length-extension attack

OPTIONS:
  --algo <algo>       Algorithm: sha256, sha512, sha3-256, md5, etc.
  --in <file>         Input file path (binary-safe)
  --text "..."        Direct UTF-8 text input
  --out <file>        Output file path
  --key <file>        Key file (for HMAC)
  --key-hex <hex>     Key in hex format (for HMAC)
  --outlen <N>        Output length in bytes (for SHAKE)
  --cert <file>       X.509 certificate file (PEM)
  --issuer-key <file> Issuer public key for signature verification
  --stream            Streaming mode (memory-efficient for large files)
  --mac <hex>         MAC value for length-extension attack
  --key-len <N>       Key length for length-extension attack
  --msg-len <N>       Original message length
  --append <str>      Data to append in length-extension attack
  --dir <path>        Directory containing collision pair files
  --encode <type>     Output encoding: hex (default), base64, raw
  --kat <file.json>   Run Known Answer Tests from JSON vector file
  --threads <N>       Number of threads (default: 1)
  --verbose           Enable detailed processing telemetry
```

---

## Example CLI Usage

### Show Help

```bash
hashtool --help
```

### Hash a File

```bash
hashtool hash --algo sha256 --in file.bin
hashtool hash --algo sha512 --in large.iso --stream
hashtool hash --algo sha256 --text "Hello World"
hashtool hash --algo sha512 --in file.bin --out digest.hex --encode hex
```

### Compute HMAC

```bash
hashtool hmac --algo sha256 --key-hex AABB --text "message"
hashtool hmac --algo sha512 --key keyfile.bin --in data.bin
```

### SHAKE Variable Output

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

---

## Performance Benchmark

The `benchmark` executable provides statistical benchmarking for hashing operations.

### Usage

```bash
benchmark [--threads N] [--iterations N] [--warm SECS] [--verbose]
```

### Methodology

Per the lab performance protocol:

1. **Warm-up**: 1–2 seconds to stabilize caches
2. **Runs**: 30+ independent timed runs
3. **Statistics reported**: Mean, Median, Standard Deviation, 95% Confidence Interval, Throughput (MB/s)

### Algorithms Benchmarked

* SHA-256
* SHA-512
* SHA3-256
* SHA3-512

### Payload Sizes

1 KiB, 100 KiB, 1 MiB, 10 MiB, 100 MiB

---

## Unit Tests

Unit tests use [Catch2 v3](https://github.com/catchorg/Catch2) via local amalgamation (headers and source in `include/catch2/`).

### Test Coverage

| Category | Tests |
|----------|-------|
| **SHA-2** | SHA-224/256/384/512 hash correctness, streaming mode |
| **SHA-3** | SHA3-224/256/384/512 hash correctness |
| **SHAKE** | SHAKE128/256 variable output length, streaming |
| **HMAC** | HMAC-SHA256/384/512 with known test vectors |
| **MD5** | MD5 hash correctness |
| **X.509** | Certificate parsing, field extraction, signature verification |
| **Length Extension** | SHA-256 length-extension attack roundtrip |
| **Negative** | Invalid algorithms, malformed certificates, wrong key |
| **KATs** | NIST FIPS 180-4, FIPS 202, RFC 1321, RFC 4231 |

---

## Project Structure

```text
Lab4_Hash_PKI/
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
│   ├── main.cpp                ← CLI entry point
│   ├── hash_engine.cpp         ← SHA-2/3/SHAKE/MD5/HMAC via Crypto++
│   ├── hash_engine.hpp
│   ├── x509_parser.cpp         ← X.509 certificate parsing (OpenSSL)
│   ├── x509_parser.hpp
│   ├── length_ext.cpp          ← SHA-256 length-extension attack
│   ├── length_ext.hpp
│   ├── utils.cpp               ← Hex/Base64/file I/O/KAT runner
│   ├── utils.hpp
│   ├── dll_wrapper.cpp         ← C exports for shared library (GUI)
│   ├── benchmark.cpp           ← Performance benchmark
│   ├── benchmark.hpp
│   ├── benchmark_main.cpp      ← Benchmark CLI
│   ├── tests.cpp               ← Catch2 unit tests
│   └── applink.c               ← OpenSSL applink (Windows)
├── demo/
│   ├── md5_collision/          ← MD5 collision pair files
│   └── tls/                    ← Nginx/Apache TLS config templates
├── test_vectors/
│   ├── sha2_kats.json          ← SHA-2 KAT vectors
│   ├── sha3_kats.json          ← SHA-3 KAT vectors
│   ├── md5_kats.json           ← MD5 KAT vectors
│   └── hmac_kats.json          ← HMAC KAT vectors
└── build/                      ← Out-of-source build output
```

---

## Known Answer Tests (KAT)

Run the bundled NIST-style vectors:

```bash
hashtool --kat test_vectors/sha2_kats.json
hashtool --kat test_vectors/sha3_kats.json
hashtool --kat test_vectors/md5_kats.json
hashtool --kat test_vectors/hmac_kats.json
```

The runner:
* Parses the JSON vector file
* Runs each test case
* Prints `PASS` or `FAIL` per case
* Prints a summary with total / passed / failed counts

---

## Practical Attack Demonstrations

### MD5 Collision

This lab demonstrates why MD5 is cryptographically broken. Two distinct files with identical MD5 digests are provided under `demo/md5_collision/`. Run the demo with:

```bash
hashtool md5-demo --dir demo/md5_collision
```

Required discussion topics include: collision vs preimage resistance differences, historical MD5 attack incidents (Wang et al. 2004, Flame malware, rogue CA certificates), and why MD5 is banned in security protocols.

### Length-Extension Attack

This attack demonstrates the vulnerability of naive `MAC = H(key || message)` constructions using Merkle-Damgård hash functions (SHA-256). Given a known MAC and the key length, an attacker can forge `H(key || message || padding || extra)` without knowing the key.

```bash
hashtool length-ext --mac 79054025255fb1a2... --key-len 14 --msg-len 5 --append "&admin=1"
```

Required discussion topics include: why Merkle-Damgård enables length extension, why HMAC prevents it, and prefix-free constructions.

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

* Hash — compute digests from text or file
* HMAC — keyed-hash message authentication
* SHAKE — extendable-output functions
* X.509 Inspector — parse and verify certificates
* MD5 Collision Demo — demonstrate MD5 weakness
* Length-Extension Attack — demonstrate naive MAC vulnerability
* Benchmark — run performance tests
* Tests — Catch2 unit tests
* KAT — Known Answer Tests

---

## Known Limitations

1. X.509 parsing requires OpenSSL to be available at build time
2. MD5 collision demo uses a fixed collision pair (Wang et al. 2004)
3. Length-extension attack only supports SHA-256 (SHA-2 family)
4. TLS configs in `demo/tls/` are templates; actual deployment requires OS-specific setup
5. Streaming SHAKE requires full file to be read (no true streaming for XOF)

---

## License

This project is provided for educational and laboratory purposes.

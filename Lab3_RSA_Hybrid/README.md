# CryptoLab3 — RSA-OAEP & Hybrid Encryption CLI

## Overview

CryptoLab3 implements RSA-OAEP encryption/decryption and hybrid encryption (RSA-OAEP + AES-256-GCM) in C++17 using the Crypto++ cryptographic library. It supports RSA-3072 and RSA-4096 key pairs, direct RSA-OAEP for small payloads, automatic hybrid envelope mode for large files, OAEP labels, AAD, JSON-based Known Answer Tests (KAT), statistical performance benchmarking, and cross-platform builds via CMake.

An optional PyQt6 GUI (`gui_qt6.py`) is provided as a bonus extension, calling the same compiled shared library (`rsatool.dll` / `librsatool.so`) through `ctypes`.

## Features

* RSA-3072 and RSA-4096 key generation
* RSA-OAEP encryption/decryption with SHA-256 hash and MGF1
* Hybrid encryption: RSA-OAEP key wrapping + AES-256-GCM payload encryption
* Automatic mode selection (direct RSA-OAEP vs hybrid envelope)
* Optional OAEP label support
* AAD (Additional Authenticated Data) for hybrid mode
* Structured envelope format (JSON header + binary payload)
* PEM and DER key format support
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
| GCC (Ubuntu) | 9+ recommended        |
| MSVC         | Visual Studio 18 2026 |
| PyQt6        | (optional, for GUI)   |

### External Dependency Layout

Crypto++ must be pre-installed under:

```text
external/
└── cryptopp/
    ├── include/
    └── lib/
        ├── libcryptopp.a   (MSYS2 / Linux)
        └── cryptopp.lib    (MSVC)
```

---

## Build Commands

### Linux (Ubuntu LTS)

```bash
cd Lab3_RSA_Hybrid
mkdir build && cd build
cmake ..
cmake --build .
```

Executables: `build/rsatool`, `build/catch2_test`, `build/benchmark`, `build/librsatool.so`

### Windows (MSVC)

```cmd
cd Lab3_RSA_Hybrid
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

Executables: `build\Release\rsatool.exe`, `build\Release\catch2_test.exe`, `build\Release\benchmark.exe`, `build\Release\rsatool.dll`

### Windows (MSYS2 / MinGW64)

```cmd
cd Lab3_RSA_Hybrid
mkdir build
cd build
cmake ..
cmake --build .
```

Executables: `build\rsatool.exe`, `build\catch2_test.exe`, `build\benchmark.exe`, `build\rsatool.dll`

### Build Targets

| Target       | Description                                       |
|--------------|---------------------------------------------------|
| `rsatool`    | Main CLI RSA-OAEP & hybrid encryption tool        |
| `rsatool_lib`| Shared library (`rsatool.dll` / `.so`) for GUI     |
| `catch2_test`| Catch2 unit test executable                       |
| `benchmark`  | Multi-threaded performance benchmark              |

---

## CLI Reference

```text
rsatool <command> [options]

COMMANDS:
  keygen              Generate RSA key pair (3072 or 4096 bits)
  encrypt             RSA-OAEP or hybrid encryption
  decrypt             RSA-OAEP or hybrid decryption

OPTIONS:
  --bits <N>          Key size: 3072 (default) or 4096
  --in <file>         Input file path (binary-safe)
  --text "..."        Direct UTF-8 text input
  --out <file>        Output file path (binary-safe)
  --pub <file>        Public key file (PEM format)
  --priv <file>       Private key file (PEM format)
  --pub-der <file>    Public key output in DER format
  --priv-der <file>   Private key output in DER format
  --label <str>       Optional OAEP label
  --aad <file>        Additional Authenticated Data from binary file
  --aad-text <str>    Additional Authenticated Data as UTF-8 string
  --encode <type>     Output encoding: hex (default), base64, raw
  --kat <file.json>   Run Known Answer Tests from JSON vector file
  --threads <N>       Number of threads (default: 1)
  --verbose           Enable detailed processing telemetry
```

---

## Example CLI Usage

### Show Help

```bash
rsatool --help
```

### Generate RSA-3072 Key Pair

```bash
rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem
```

### Encrypt Small Message (Direct RSA-OAEP)

```bash
rsatool encrypt --text "Hello, RSA!" --pub pub.pem --out ct.bin
```

### Encrypt with OAEP Label

```bash
rsatool encrypt --in msg.txt --pub pub.pem --out ct.bin --label "MyLabel"
```

### Encrypt Large File (Auto Hybrid Mode)

```bash
rsatool encrypt --in large_file.bin --pub pub.pem --out envelope.bin
```

### Hybrid Encryption with AAD

```bash
rsatool encrypt --in msg.bin --pub pub.pem --out env.bin --aad-text "metadata"
```

### Decrypt (Auto-detects RSA-OAEP or Hybrid)

```bash
rsatool decrypt --in ct.bin --priv priv.pem --out msg.txt
```

### Decrypt with Label

```bash
rsatool decrypt --in ct.bin --priv priv.pem --out msg.txt --label "MyLabel"
```

### Base64 Output

```bash
rsatool encrypt --text "test" --pub pub.pem --encode base64
```

### Run NIST KAT Tests

```bash
rsatool --kat test_vectors/rsa_oaep_kats.json
```

---

## Performance Benchmark

The `benchmark` executable provides statistical benchmarking for RSA key generation, RSA-OAEP encryption/decryption, and hybrid encryption.

### Usage

```bash
benchmark [--threads N] [--iterations N] [--keysize N] [--warm SECS] [--verbose]
```

### Methodology

Per the lab performance protocol:

1. **Warm-up**: 1–2 seconds to stabilize caches
2. **Block size**: ~1,000 operations per block (keygen, encrypt, decrypt)
3. **Runs**: 30+ independent timed runs
4. **Statistics reported**: Mean, Median, Standard Deviation, 95% Confidence Interval, Throughput (MB/s)

### Benchmarked Operations

* RSA-3072 and RSA-4096 key generation
* RSA-OAEP encryption/decryption (small messages)
* Hybrid encrypt/decrypt at payload sizes: 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB, 100 MiB

### Multi-threading

Use `--threads N` to scale across CPU cores. Set to `0` for auto-detection.

---

## Unit Tests

Unit tests use [Catch2 v3](https://github.com/catchorg/Catch2) via local amalgamation (headers and source in `include/catch2/`).

### Test Coverage

| Category | Tests |
|----------|-------|
| **RSA Key Generation** | Valid sizes (3072, 4096), invalid sizes rejected |
| **RSA-OAEP Encrypt/Decrypt** | Small message, empty message, medium message, label roundtrip |
| **RSA-OAEP Negative** | Wrong key fails, wrong label fails, tampered ciphertext fails, invalid length rejected |
| **Hybrid Encrypt/Decrypt** | 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB, empty payload, with AAD |
| **Hybrid Negative** | Tampered ciphertext → auth failure, tampered header → failure, wrong key → failure |
| **DER Format** | Public/private key DER roundtrip |
| **Encoding** | Hex and Base64 roundtrip |

---

## Project Structure

```text
Lab3_RSA_Hybrid/
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
│   ├── rsa_engine.cpp          ← RSA-OAEP encrypt/decrypt core
│   ├── rsa_engine.hpp
│   ├── hybrid_engine.cpp       ← Hybrid encryption (RSA + AES-GCM)
│   ├── hybrid_engine.hpp
│   ├── utils.cpp               ← Hex/Base64/file I/O/KAT runner
│   ├── utils.hpp
│   ├── dll_wrapper.cpp         ← C exports for shared library (GUI)
│   ├── benchmark.cpp           ← Performance benchmark
│   ├── benchmark.hpp
│   ├── benchmark_main.cpp      ← Benchmark CLI
│   └── tests.cpp               ← Catch2 unit tests
├── test_vectors/
│   ├── rsa_oaep_kats.json      ← RSA-OAEP KAT vectors
│   └── hybrid_kats.json        ← Hybrid KAT vectors
└── build/                      ← Out-of-source build output
```

---

## Hybrid Encryption Envelope Format

### Envelope Binary Structure

```
┌────────────────────────────────────────────────────────────────────┐
│  [4 bytes]  header_size (uint32, little-endian)                    │
├────────────────────────────────────────────────────────────────────┤
│  [header_size bytes]  JSON header (UTF-8)                          │
│    {                                                               │
│      "mode":        "RSA-OAEP-AES-GCM",                            │
│      "rsa_modulus": 3072,                                          │
│      "hash":        "SHA-256",                                     │
│      "wrapped_key": "<base64 RSA-encrypted AES key>",              │
│      "iv":          "<base64 96-bit nonce>",                       │
│      "tag":         "<base64 128-bit GCM tag>",                    │
│      "aad":         "<base64 AAD or empty string>"                 │
│    }                                                               │
├────────────────────────────────────────────────────────────────────┤
│  [remaining bytes]  AES-GCM ciphertext (raw binary)                │
└────────────────────────────────────────────────────────────────────┘
```

### Auto-Mode Selection

| Condition | Mode Selected |
|-----------|---------------|
| Plaintext ≤ max size (318 bytes for RSA-3072) AND no AAD | **Direct RSA-OAEP** |
| Plaintext > max size | **Hybrid (RSA-OAEP + AES-GCM)** |
| AAD provided (any plaintext size) | **Hybrid (RSA-OAEP + AES-GCM)** |

### Security Properties

| Property | Value |
|----------|-------|
| Key wrapping | RSA-OAEP-3072 (SHA-256, MGF1) |
| Payload cipher | AES-256-GCM |
| Session key | 256-bit random (fresh per encryption) |
| IV / Nonce | 96-bit random (unique per encryption) |
| Auth tag | 128-bit GCM tag |
| AAD support | Yes (authenticated, not encrypted) |
| Confidentiality | IND-CCA2 (via RSA-OAEP) + IND-CPA (via AES-GCM) |
| Integrity | 128-bit GCM authentication tag |

---

## Known Answer Tests (KAT)

Run the bundled NIST-style vectors:

```bash
rsatool --kat test_vectors/rsa_oaep_kats.json
rsatool --kat test_vectors/hybrid_kats.json
```

The runner:
* Parses the JSON vector file
* Runs each test case (encrypt + decrypt, compare)
* Prints `PASS` or `FAIL` per case
* Prints a summary with total / passed / failed counts

Coverage includes:
* RSA-OAEP at various payload sizes
* Hybrid encryption at sizes: 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB
* Payloads with AAD
* Negative tests (wrong key, tampered data, invalid lengths)

---

## Python GUI (Bonus)

The optional GUI is implemented in `gui_qt6.py` using PyQt6 and `ctypes`. It auto-discovers the built shared library (`rsatool.dll` on Windows, `librsatool.so` on Linux) on startup.

### Requirements

```bash
pip install PyQt6
```

### Running the GUI

```bash
python gui_qt6.py
```

The GUI provides tabs for: Key Generation, Encryption, Decryption, Hybrid Mode, Benchmark, Unit Tests, and KAT Tests.

---

## Known Limitations

1. Only RSA-3072 and RSA-4096 key sizes are supported (per lab requirements)
2. PEM format uses simple Base64 encoding (not full PKCS#8)
3. No support for password-protected private keys
4. Single-threaded implementations
5. RSA key generation is computationally expensive and may take 30+ seconds for 4096-bit keys

---

## License

This project is provided for educational and laboratory purposes.

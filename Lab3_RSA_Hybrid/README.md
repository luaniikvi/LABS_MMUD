# Lab 3 — RSA-OAEP & Hybrid Encryption

## Overview

This lab implements RSA-OAEP encryption/decryption and hybrid encryption (RSA-OAEP + AES-GCM) using Crypto++.

## Features

- **RSA Key Generation**: 3072-bit and 4096-bit keys
- **RSA-OAEP Encryption**: Using SHA-256 hash and MGF1
- **Hybrid Encryption**: RSA-OAEP for key wrapping + AES-256-GCM for data
- **Envelope Format**: JSON header with binary payload
- **AAD Support**: Additional authenticated data for hybrid mode
- **NIST KAT Validation**: Known Answer Tests for both RSA and hybrid modes
- **Comprehensive Negative Testing**: Wrong keys, tampered ciphertext, invalid inputs
- **Performance Benchmarking**: Statistical analysis with 95% confidence intervals

## Dependencies

- C++17 or later
- CMake 3.15+
- Crypto++ (provided in `../external/cryptopp`)
- Catch2 (local amalgamation in `include/catch2/`)
- nlohmann/json (local header in `include/nlohmann/`)

## Build Instructions

### Windows (MSVC)

```cmd
cd Lab3_RSA_Hybrid
mkdir build_msvc
cd build_msvc
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Windows (MinGW/MSYS2)

Open MSYS2 MinGW64 terminal:

```bash
cd Lab3_RSA_Hybrid
mkdir build_mingw
cd build_mingw
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Linux (Ubuntu LTS)

```bash
cd Lab3_RSA_Hybrid
mkdir build
cd build
cmake ..
cmake --build .
```

### Quick Build (PowerShell)

```powershell
# MSVC (default)
.\build_lab3.ps1

# MinGW
.\build_lab3.ps1 -Compiler mingw
```

**See [BUILD_GUIDE.md](BUILD_GUIDE.md) for detailed build instructions.**

## Python Qt6 GUI

A simple Qt6 GUI is provided that calls the compiled `rsatool` executable (does not duplicate cryptographic logic).

### Installation

```bash
pip install -r requirements.txt
```

### Run GUI

```bash
python gui_qt6.py
```

### GUI Features
- **Key Generation**: Generate RSA-3072/4096 key pairs
- **Encryption**: Encrypt text or files using RSA-OAEP or hybrid mode
- **Decryption**: Decrypt RSA-OAEP or hybrid envelopes
- **OAEP Label Support**: Optional label parameter
- **Background Processing**: Non-blocking crypto operations
- **Output Log**: Real-time operation logging

## CLI Usage

### Key Generation

```bash
# Generate RSA-3072 key pair
rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem

# Generate RSA-4096 key pair
rsatool keygen --bits 4096 --pub pub.pem --priv priv.pem
```

### Encryption

```bash
# Direct RSA-OAEP encryption (small messages ≤ 382 bytes for RSA-3072)
rsatool encrypt --in msg.txt --pub pub.pem --out ct.bin

# Encryption from text
rsatool encrypt --text "Hello, RSA!" --pub pub.pem --out ct.bin

# With OAEP label
rsatool encrypt --in msg.txt --pub pub.pem --out ct.bin --label "MyLabel"

# Hybrid encryption (automatic for large files)
rsatool encrypt --in large_file.bin --pub pub.pem --out envelope.bin

# Hybrid with AAD
rsatool encrypt --in msg.bin --pub pub.pem --out env.bin --aad-text "metadata"
```

### Decryption

```bash
# Decrypt (auto-detects RSA-OAEP or hybrid envelope)
rsatool decrypt --in ct.bin --priv priv.pem --out msg.txt

# Decrypt with label
rsatool decrypt --in ct.bin --priv priv.pem --out msg.txt --label "MyLabel"
```

### Output Encoding

```bash
# Display ciphertext in hex (default)
rsatool encrypt --text "test" --pub pub.pem --encode hex

# Display ciphertext in base64
rsatool encrypt --text "test" --pub pub.pem --encode base64

# Write raw binary to file
rsatool encrypt --text "test" --pub pub.pem --out ct.bin --encode raw
```

## Running Tests

### Unit Tests & KATs

```bash
cd build
ctest -V
```

Or run the test executable directly:

```bash
# Windows
.\test_lab3.exe

# Linux
./test_lab3
```

### Known Answer Tests

KAT vectors are located in `test_vectors/`:
- `rsa_oaep_kats.json` - RSA-OAEP test vectors
- `hybrid_kats.json` - Hybrid encryption test vectors

## Benchmarking

```bash
# Run full benchmark suite
./benchmark_lab3
```

The benchmark measures:
- RSA key generation (3072 vs 4096 bits)
- RSA-OAEP encryption/decryption latency
- Hybrid encryption/decryption throughput
- Statistical metrics: mean, median, std dev, 95% CI

Payload sizes tested: 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB

## Envelope Format

Hybrid encryption produces a binary envelope with this structure:

```
[4 bytes: header size][JSON header][AES-GCM ciphertext]
```

JSON header example:
```json
{
  "mode": "RSA-OAEP-AES-GCM",
  "rsa_modulus": 3072,
  "hash": "SHA-256",
  "wrapped_key": "<base64>",
  "iv": "<base64>",
  "tag": "<base64>",
  "aad": "<base64 or empty>"
}
```

## Security Properties

### RSA-OAEP
- **IND-CCA2 secure**: Optimal Asymmetric Encryption Padding
- **Hash**: SHA-256
- **MGF**: MGF1 with SHA-256
- **Max plaintext**: k - 2*hLen - 2 bytes (382 bytes for RSA-3072)

### Hybrid Mode
- **Key wrapping**: RSA-OAEP-3072 with SHA-256
- **Data encryption**: AES-256-GCM
- **IV**: 96-bit random nonce per encryption
- **Authentication**: 128-bit GCM tag
- **AAD**: Optional additional authenticated data

## Negative Testing

The implementation includes comprehensive negative tests:
- ✅ Wrong key decryption → fails securely
- ✅ Tampered ciphertext (RSA) → padding validation failure
- ✅ Tampered ciphertext (AES-GCM) → authentication tag failure
- ✅ Plaintext too large for direct RSA → fails with clear error
- ✅ Invalid ciphertext length → rejection
- ✅ Malformed PEM keys → parsing failure

## Project Structure

```
Lab3_RSA_Hybrid/
├── CMakeLists.txt              # Build configuration
├── README.md                   # This file
├── src/
│   ├── main.cpp                # CLI tool entry point
│   ├── rsa_engine.cpp          # RSA-OAEP implementation
│   ├── rsa_engine.hpp
│   ├── hybrid_engine.cpp       # Hybrid encryption implementation
│   ├── hybrid_engine.hpp
│   ├── utils.cpp               # Utility functions (hex, base64, I/O)
│   ├── utils.hpp
│   ├── benchmark.cpp           # Benchmarking implementation
│   ├── benchmark.hpp
│   ├── benchmark_main.cpp      # Benchmark executable
│   └── tests.cpp               # Catch2 unit tests & KATs
├── include/
│   ├── catch2/                 # Catch2 amalgamation
│   └── nlohmann/               # JSON library
└── test_vectors/
    ├── rsa_oaep_kats.json      # RSA-OAEP KAT vectors
    └── hybrid_kats.json        # Hybrid KAT vectors
```

## Known Limitations

- Only RSA-3072 and RSA-4096 are supported (per lab requirements)
- PEM format uses simple Base64 encoding (not full ASN.1/DER parsing)
- No support for encrypted private keys (password protection)
- Single-threaded implementation

## Report Requirements

See the main project README for report structure and requirements.

## Academic Integrity

This implementation is for educational purposes only. All cryptographic operations use established libraries (Crypto++) and follow NIST standards.

## License

Educational use only. See project-level licensing.

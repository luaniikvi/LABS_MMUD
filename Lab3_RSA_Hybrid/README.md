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
cmake ..
cmake --build . --config Release
```

### Windows (MinGW/MSYS2)

Open MSYS2 MinGW64 terminal:

```bash
cd Lab3_RSA_Hybrid
mkdir build_mingw
cd build_mingw
cmake ..
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
- **Hybrid Mode**: Dedicated hybrid encrypt/decrypt with AAD support, envelope inspection, and mode auto-detection
- **Benchmark**: Run performance benchmarks for RSA key generation, RSA-OAEP, and hybrid encryption with statistical output
- **Catch2 Tests**: Run the full Catch2 unit test suite including RSA-OAEP, hybrid, negative, encoding, and DER tests
- **KAT Tests**: Run Known Answer Tests against `rsa_oaep_kats.json` and `hybrid_kats.json` vector files
- **OAEP Label Support**: Optional label parameter
- **Background Processing**: Non-blocking crypto operations via QThread
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

Payload sizes tested: 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB, 100 MiB

## Hybrid Encryption

### Overview

Hybrid encryption combines the strengths of asymmetric (RSA-OAEP) and symmetric (AES-256-GCM) cryptography. RSA is used only to securely transport a randomly generated AES session key, while the actual payload is encrypted with high-throughput AES-GCM. This architecture eliminates RSA's plaintext-size limitation and provides authenticated encryption for arbitrarily large data.

### Architecture Flow

```
ENCRYPTION (Sender):
  1. Generate random 256-bit AES session key
  2. Wrap (encrypt) AES key with RSA-OAEP using recipient's public key
  3. Generate random 96-bit IV (nonce)
  4. Encrypt payload with AES-256-GCM (key + IV)
  5. Compute 128-bit GCM authentication tag
  6. Package into binary envelope: [header_size][JSON header][ciphertext]

DECRYPTION (Recipient):
  1. Parse envelope → extract wrapped key, IV, tag, AAD, ciphertext
  2. Unwrap (decrypt) AES key with RSA-OAEP using private key
  3. Decrypt ciphertext with AES-256-GCM (key + IV + tag)
  4. Verify GCM authentication tag (rejects tampered data)
  5. Output plaintext
```

### Auto-Mode Selection

The tool automatically selects between direct RSA-OAEP and hybrid encryption:

| Condition | Mode Selected |
|-----------|---------------|
| Plaintext ≤ max size (318 bytes for RSA-3072) AND no AAD | **Direct RSA-OAEP** |
| Plaintext > max size | **Hybrid (RSA-OAEP + AES-GCM)** |
| AAD provided (any plaintext size) | **Hybrid (RSA-OAEP + AES-GCM)** |

Max plaintext sizes:
- **RSA-3072**: `384 - 2×32 - 2 = 318 bytes`
- **RSA-4096**: `512 - 2×32 - 2 = 446 bytes`

### AAD (Additional Authenticated Data)

Hybrid mode supports optional AAD — data that is authenticated (integrity-checked) but **not encrypted**. This is useful for binding metadata (e.g., message type, sender ID, protocol version) to the ciphertext without hiding it.

```bash
# Encrypt with AAD string
rsatool encrypt --in data.bin --pub pub.pem --out env.bin --aad-text "protocol=v2;sender=alice"

# Encrypt with AAD from file
rsatool encrypt --in data.bin --pub pub.pem --out env.bin --aad metadata.bin
```

AAD is stored in the envelope header (base64-encoded). During decryption, the embedded AAD is automatically used for GCM tag verification. If the envelope is tampered with or AAD is modified, decryption fails with an authentication error.

### OAEP Label in Hybrid Mode

The OAEP label is cryptographically bound to the RSA key-wrapping step. If a label is used during encryption, the **same label must be provided during decryption** — otherwise RSA-OAEP unwrapping fails, and the AES key cannot be recovered.

```bash
# Hybrid with label
rsatool encrypt --in large.bin --pub pub.pem --out env.bin --label "session-42"
rsatool decrypt --in env.bin --priv priv.pem --out out.bin --label "session-42"
```

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
| Forward secrecy | Per-message random AES key |

### Performance Characteristics

Hybrid encryption throughput is dominated by AES-GCM performance (fast, hardware-accelerated on modern CPUs). RSA overhead is constant (~384 bytes for key wrapping) regardless of payload size, making hybrid mode efficient for large files:

| Payload Size | Typical Throughput | RSA Overhead |
|-------------|--------------------|-------------|
| 1 KiB       | ~hundreds of MB/s  | ~384 bytes  |
| 1 MiB       | ~GB/s (AES-NI)     | ~384 bytes  |
| 100 MiB     | ~GB/s (AES-NI)     | ~384 bytes  |

### Envelope Binary Format

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

### KAT Validation (Hybrid)

Hybrid KAT vectors are in `test_vectors/hybrid_kats.json` and cover:
- Various payload sizes: 1 KiB, 4 KiB, 16 KiB, 256 KiB, 1 MiB
- Payloads with AAD
- Binary payloads (raw hex)

Run hybrid KATs:
```bash
rsatool --kat test_vectors/hybrid_kats.json
```

## Security Properties

### RSA-OAEP
- **IND-CCA2 secure**: Optimal Asymmetric Encryption Padding
- **Hash**: SHA-256
- **MGF**: MGF1 with SHA-256
- **Max plaintext**: k - 2*hLen - 2 bytes (318 bytes for RSA-3072)

### Negative Testing

The implementation includes comprehensive negative tests:
- ✅ Wrong key decryption → fails securely (RSA padding error / GCM auth failure)
- ✅ Tampered ciphertext (RSA) → padding validation failure
- ✅ Tampered ciphertext (AES-GCM) → authentication tag failure
- ✅ Tampered envelope header → decryption rejected
- ✅ Wrong OAEP label → unwrapping failure in both RSA and hybrid modes
- ✅ Plaintext too large for direct RSA → fails with clear error
- ✅ Invalid ciphertext length → rejection
- ✅ Malformed / corrupted PEM keys → parsing failure

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

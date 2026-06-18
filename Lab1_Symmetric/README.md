# CryptoLab1 — AES Symmetric Encryption CLI

## Overview

CryptoLab1 is a command-line AES encryption/decryption tool implemented in C++17 using the Crypto++ cryptographic library. It supports all common AES operating modes, authenticated encryption (AEAD), file and text inputs, JSON-based Known Answer Tests (KAT), statistical performance benchmarking, and cross-platform builds via CMake.

An optional PyQt6 GUI (`gui_qt6.py`) is provided as a bonus extension, calling the same compiled shared library (`aestool.dll` / `libaestool.so`) through `ctypes` — no cryptographic logic is duplicated in Python.

## Features

* AES-128 / AES-192 / AES-256 key sizes
* Cipher modes: ECB, CBC, CTR, OFB, CFB, XTS, GCM, CCM
* AEAD authentication support (GCM, CCM) with `--aead` flag
* Hex, Base64, and raw output encoding
* File-based (`--in`) and direct text (`--text`) input
* JSON sidecar metadata generation (auto-loaded on decrypt)
* NIST KAT (Known Answer Test) runner (`--kat`)
* Multi-threaded performance benchmark (`aestool_bench`)
* Catch2 unit tests with per-test PASS/FAIL output
* Cross-platform build support (MSVC, MinGW64, GCC/Linux)
* Out-of-source CMake builds enforced
* Optional PyQt6 GUI bonus

---

## Dependencies

| Dependency   | Version             |
|--------------|---------------------|
| C++ Standard | C++17               |
| CMake        | 3.15 or newer       |
| Crypto++     | 8.x or newer        |
| GCC (Ubuntu) | 9+ recommended      |
| MSVC         | Visual Studio 2017+ |
| MinGW-w64    | GCC 9+ recommended  |
| PyQt6        | (optional, for GUI) |

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
mkdir build && cd build
cmake ..
cmake --build .
```

Executables: `build/aestool`, `build/aestool_tests`, `build/aestool_bench`, `build/libaestool.so`

### Windows (MSVC)

```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

Executables: `build\Release\aestool.exe`, `build\Release\aestool_tests.exe`, `build\Release\aestool_bench.exe`, `build\Release\aestool.dll`

### Windows (MSYS2 / MinGW64)

```cmd
mkdir build
cd build
cmake ..
cmake --build .
```

Executables: `build\aestool.exe`, `build\aestool_tests.exe`, `build\aestool_bench.exe`, `build\aestool.dll`

### Build Targets

| Target          | Description                                       |
|-----------------|---------------------------------------------------|
| `aestool`       | Main CLI encryption/decryption tool               |
| `aestool_lib`   | Shared library (`aestool.dll` / `.so`) for GUI    |
| `aestool_tests` | Catch2 unit test executable                       |
| `aestool_bench` | Multi-threaded performance benchmark              |

---

## CLI Reference

```text
aestool <command> [options]

COMMANDS:
  encrypt             Symmetric encryption (Plaintext → Ciphertext)
  decrypt             Symmetric decryption (Ciphertext → Plaintext)

OPTIONS:
  --in <file>         Input file path (binary-safe)
  --text "..."        Direct UTF-8 text input
  --out <file>        Output file path (binary-safe)
  --key <file>        Key file (raw binary or hex-encoded with header)
  --key-hex <hex>     Key in hex format
  --iv <file|hex>     IV/nonce: file (binary/hex header) or inline hex
  --nonce <file|hex>  Alias for --iv
  --aad <file>        Additional Authenticated Data from binary file
  --aad-text <str>    Additional Authenticated Data as UTF-8 string
  --mode <MODE>       Cipher mode: ecb, cbc, ctr, ofb, cfb, xts, gcm, ccm
  --aead              Enable AEAD authenticated encryption
  --tag-hex <hex>     Authentication tag in hex (for AEAD decryption)
  --encode <type>     Output encoding: hex, base64, base, raw (default: hex)
  --threads <N>       Number of threads (default: 1)
  --kat <file.json>   Run NIST Known Answer Tests from JSON vector file
  --verbose           Enable detailed processing telemetry
  --allow-ecb         Bypass ECB size restriction (> 16 KiB)
```

---

## Example CLI Usage

### Show Help

```bash
aestool --help
```

### Encrypt Text (GCM)

```bash
aestool encrypt \
  --mode gcm \
  --text "Confidential Data" \
  --key-hex 00112233445566778899AABBCCDDEEFF \
  --iv 00112233445566778899AABB \
  --aead
```

### Encrypt File (CBC)

```bash
aestool encrypt \
  --mode cbc \
  --in plaintext.bin \
  --out ciphertext.bin \
  --key-hex 00112233445566778899AABBCCDDEEFF \
  --iv 0102030405060708090A0B0C0D0E0F10
```

### Decrypt File (auto-loads sidecar JSON)

```bash
aestool decrypt \
  --mode cbc \
  --in ciphertext.bin \
  --out recovered.bin \
  --key-hex 00112233445566778899AABBCCDDEEFF
```

> When a sidecar `ciphertext.bin.json` exists, IV/nonce, tag, AAD, and mode are auto-loaded.

### Decrypt with Explicit Tag (GCM)

```bash
aestool decrypt \
  --mode gcm \
  --in ct.bin \
  --out msg.txt \
  --key-hex 00112233445566778899AABBCCDDEEFF \
  --tag-hex <tag_hex> \
  --aead
```

### Base64 Output

```bash
aestool encrypt \
  --mode ctr \
  --text "Hello World" \
  --encode base64
```

### Encrypt with AAD (GCM)

```bash
aestool encrypt \
  --mode gcm \
  --text "Secret" \
  --key-hex 00112233445566778899AABBCCDDEEFF \
  --iv 00112233445566778899AABB \
  --aad-text "Authenticated Header" \
  --aead
```

### Run NIST KAT Tests

```bash
aestool --kat SampleData/vectors.json
```

### Verbose Mode

```bash
aestool encrypt \
  --mode gcm \
  --text "secret" \
  --key-hex 00112233445566778899AABBCCDDEEFF \
  --iv 00112233445566778899AABB \
  --aead \
  --verbose
```

---

## Performance Benchmark

The `aestool_bench` executable provides multi-threaded statistical benchmarking across all AES modes and payload sizes.

### Usage

```bash
aestool_bench [--threads N] [--mode MODE]
```

### Methodology

Per the lab performance protocol:

1. **Warm-up**: 1–2 seconds to stabilize caches
2. **Block size**: ~1,000 encrypt+decrypt operations per block
3. **Runs**: 30+ independent timed runs
4. **Statistics reported**: Mean, Median, Standard Deviation, 95% Confidence Interval, Throughput (MB/s)

### Payload Sizes

1 KB, 4 KB, 16 KB, 256 KB, 1 MB, 8 MB

### Modes Benchmarked

All 8 modes: ECB, CBC, CTR, OFB, CFB, XTS, GCM, CCM

### Multi-threading

Use `--threads N` to scale across CPU cores. Each thread receives a unique IV suffix to avoid nonce-reuse collisions.

---

## Unit Tests

Unit tests use [Catch2 v3](https://github.com/catchorg/Catch2) via local amalgamation (headers and source in `include/catch2/`).

### Build and Run

```bash
mkdir build && cd build
cmake ..

# Build tests
cmake --build . --target aestool_tests

# Run all tests via CTest
ctest --output-on-failure

# Run with verbose output (shows each test's stdout/stderr)
ctest -V

# Or run directly for per-test PASS/FAIL output
./aestool_tests
```

### Test Coverage

| Category | Tests |
|----------|-------|
| **NIST SP 800-38A KATs** | CBC-AES128, CBC-AES256, CTR-AES128, CTR-AES256, OFB-AES128, OFB-AES256, CFB128-AES128, CFB128-AES256, ECB-AES128 |
| **NIST GCM KATs** | TC1 (empty pt/aad), TC2 (pt only), TC3 (full pt), TC4 (pt + AAD) |
| **CCM** | Encrypt/Decrypt roundtrip, tampered tag rejected |
| **XTS** | AES-256-XTS roundtrip (64-byte key) |
| **ECB restrictions** | Fails closed on >16 KiB without `--allow-ecb`; succeeds with override |
| **IV length enforcement** | CBC rejects 8-byte IV, GCM rejects 16-byte IV, CTR rejects 8-byte IV |
| **Invalid key size** | CBC rejects 3-byte key, GCM rejects 10-byte key |
| **GCM AEAD negative** | Tampered ciphertext → auth failure, tampered tag → failure, wrong key → failure, wrong AAD → failure |
| **CBC non-AEAD negative** | Wrong key → incorrect plaintext, wrong IV → incorrect plaintext, tampered ciphertext → corrupted output |
| **CTR** | Roundtrip correctness, wrong IV → wrong plaintext |
| **OFB** | Encrypt/Decrypt roundtrip |
| **AEAD flag enforcement** | GCM without `--aead` rejected, CCM without `--aead` rejected |

---

## Project Structure

```text
Lab1_Symmetric/
├── CMakeLists.txt              ← Build system (all targets)
├── gui_qt6.py                  ← Optional PyQt6 GUI (bonus)
├── SampleData/
│   └── vectors.json            ← NIST KAT test vectors
├── include/
│   ├── catch2/
│   │   ├── catch_amalgamated.hpp
│   │   └── catch_amalgamated.cpp
│   ├── nlohmann/
│   │   └── json.hpp
│   └── dll_export.hpp          ← DLL export macros
├── src/
│   ├── main.cpp                ← CLI entry point
│   ├── crypto_engine.cpp       ← AES encrypt/decrypt core
│   ├── crypto_engine.hpp       ← CryptoConfig struct & function declarations
│   ├── utils.cpp               ← Hex/Base64/file I/O/sidecar JSON/KAT runner
│   ├── utils.hpp
│   ├── dll_wrapper.cpp         ← C exports for shared library (GUI)
│   ├── benchmark.cpp           ← Multi-threaded performance benchmark
│   └── tests.cpp               ← Catch2 unit tests
└── build/                      ← Out-of-source build output
```

---

## Misuse Prevention

### ECB Restrictions

When `--mode ecb` is selected:

* A `[WARNING]` is printed to stderr on both encrypt and decrypt.
* Inputs larger than **16 KiB** are rejected unless `--allow-ecb` is supplied.
* All rejections fail closed (non-zero exit, no output file written).

### IV / Nonce Handling

Per-mode IV length enforcement:

| Mode                  | IV length   |
|-----------------------|-------------|
| CBC, CTR, OFB, CFB    | 16 bytes    |
| XTS                   | 16 bytes    |
| GCM                   | 12 bytes    |
| CCM                   | 7–13 bytes  |
| ECB                   | not used    |

If IV/nonce is omitted (except ECB):

* A cryptographically secure value is generated via Crypto++ `AutoSeededRandomPool`.
* The IV is persisted to the sidecar JSON (`<out>.json`) when `--out` is used.
* When printing to stdout, `[IV-HEX]:` is emitted after the ciphertext.

IV/nonce may be supplied as:

* `--iv <file>` / `--nonce <file>` — raw binary file or hex-encoded file with header (`# HEX …`, `HEX:…`)
* Inline hex string (when the path does not exist as a file)

Invalid IV lengths are rejected before any cryptographic operation.

### Nonce Reuse Protection (CTR, GCM, CCM)

Before each encryption with CTR, GCM, or CCM, the engine checks whether the `(key, nonce)` pair was previously used.

**Detection logic:**

1. Build a token: `hex(key) + "||" + hex(nonce)`.
2. Compare against an in-process registry loaded at first check.
3. Also load entries from `.aestool_nonce_registry.json` in the working directory (written by prior encrypt operations).
4. If a match is found → reject with `CRITICAL SECURITY VIOLATION: Detected reuse of (Key, Nonce) pair!`
5. After a successful encrypt, register the pair in memory and append to `.aestool_nonce_registry.json`.

#### `.aestool_nonce_registry.json` File Format

This file is a persistent nonce reuse protection registry stored in the working directory. It tracks every `(key, nonce)` pair that has been used for encryption in AEAD modes (GCM, CCM) and CTR mode.

**Purpose:** In AES-GCM/CCM/CTR, reusing the same `(key, nonce/IV)` pair is catastrophic — it completely breaks confidentiality and authentication. This file prevents nonce reuse attacks across multiple `aestool` invocations by persisting the registry to disk.

**File format:**

```json
{
  "entries": [
    {
      "key": "69FD0C4F9C74ECBD...",   // AES key (hex)
      "mode": "gcm",                    // Cipher mode used
      "nonce": "07913CACBF872E..."     // IV/nonce used (hex)
    }
  ]
}
```

**Fields:**

| Field     | Description                                      |
|-----------|--------------------------------------------------|
| `key`     | The AES encryption key in hex format              |
| `mode`    | The cipher mode (`gcm`, `ccm`, `ctr`)            |
| `nonce`   | The IV/nonce value in hex format                  |

**Lifecycle:**

- **Created** automatically on first encryption with CTR/GCM/CCM mode.
- **Updated** after each successful encryption — the `(key, nonce, mode)` tuple is appended.
- **Loaded** at startup and checked before each encryption to detect reuse.
- **Can be safely deleted** if you are certain all future operations will use fresh nonces.

### Key File Formats

`--key KEYFILE` accepts:

* **Raw binary** — e.g. a 32-byte AES-256 key file
* **Hex-encoded with header** — lines starting with `#` or `HEX:` followed by hex digits

`--key-hex HEXSTRING` accepts inline hex directly.

Valid AES key sizes: 16 bytes (128-bit), 24 bytes (192-bit), 32 bytes (256-bit). XTS requires 32 or 64 bytes. Invalid key sizes are rejected before any operation.

---

## Sidecar JSON Header

When encrypting with `--out ct.bin`, a metadata file `ct.bin.json` is written:

```json
{
  "alg": "AES-256-GCM",
  "mode": "gcm",
  "iv": "...hex...",
  "aad": "...hex...",
  "tag": "...hex..."
}
```

Fields:

* **alg** — full algorithm identifier (e.g. `AES-256-GCM`)
* **mode** — cipher mode (`gcm`, `cbc`, …)
* **iv** — IV/nonce in hex
* **aad** — additional authenticated data in hex (empty string if none)
* **tag** — authentication tag in hex (AEAD modes only)

On decrypt, metadata is auto-loaded from `<in>.json` when present, populating IV, tag, AAD, and mode if not explicitly provided via CLI.

---

## Known Answer Tests (KAT)

Run the bundled NIST-style vectors:

```bash
aestool --kat SampleData/vectors.json
```

The runner:

* Parses the JSON vector file
* Runs each test case (decrypt + compare)
* Prints `PASS` or `FAIL` per case
* Prints a summary with total / passed / failed counts

Coverage includes NIST SP 800-38A modes (CBC, CFB, OFB, CTR), GCM, CCM, and negative tests:

* Wrong key → incorrect plaintext or padding error
* Wrong IV → incorrect plaintext
* Tampered ciphertext (non-AEAD) → corrupted output / padding failure
* Tampered ciphertext (AEAD) → authentication failure
* Invalid tag → decryption refused
* Invalid IV length → rejection before decrypt

All malformed inputs fail closed (non-zero exit, no output written).

---

## Python GUI (Bonus)

The optional GUI is implemented in `gui_qt6.py` using PyQt6 and `ctypes`. It auto-discovers the built shared library (`aestool.dll` on Windows, `libaestool.so` on Linux) on startup.

### Requirements

```bash
pip install PyQt6
```

### Running the GUI

```bash
python gui_qt6.py
```

The GUI will:
1. Automatically search for the compiled shared library (`aestool.dll` / `libaestool.so`) in the `build/` directory.
2. Load the library and configure the AES C-wrapper functions.
3. Print a success status in the log console at the bottom.

### Custom Library Path

If the shared library is in a non-standard location:
1. Go to the **Core Library Configuration** card on the left panel.
2. Click **Browse DLL** → select your `.dll` or `.so` file.
3. Click **Load DLL** → the library is reloaded dynamically.

### DLL Runtime Dependencies (Windows)

On Windows, the compiled library may require MinGW runtime DLLs. If a loading error occurs, ensure your MinGW/MSYS2 bin directory is added to your environment `PATH`:

```powershell
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
python gui_qt6.py
```

---

## Known Limitations

1. Crypto++ must be pre-built and placed under `external/cryptopp/` before configuring CMake.
2. Multi-threading (`--threads`) is parsed by the CLI but may not provide performance improvements for every cipher mode.
3. XTS mode requires either a 32-byte or 64-byte key (two AES keys).
4. GCM expects exactly a 12-byte IV.
5. CCM accepts IV lengths between 7 and 13 bytes.
6. ECB mode is intentionally restricted for large inputs unless `--allow-ecb` is explicitly supplied.
7. The nonce reuse registry (`.aestool_nonce_registry.json`) is file-based and local to the working directory; it is not shared across processes automatically.

---

## License

This project is provided for educational and laboratory purposes.

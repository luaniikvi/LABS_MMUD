# CryptoLab1 - AES Symmetric Encryption CLI

## Overview

CryptoLab1 is a command-line AES encryption/decryption utility implemented in C++17 using the Crypto++ cryptographic library. The tool supports multiple AES operating modes, authenticated encryption modes (AEAD), file and text inputs, JSON-based Known Answer Tests (KAT), and cross-platform builds using CMake.

## Features

* AES-128 / AES-192 / AES-256 support
* Cipher modes:

  * ECB
  * CBC
  * CTR
  * OFB
  * CFB
  * XTS
  * GCM
  * CCM
* AEAD authentication support (GCM, CCM)
* Hex and Base64 output encoding
* File-based and direct text input
* JSON sidecar metadata generation
* NIST KAT (Known Answer Test) execution
* Cross-platform build support
* Out-of-source CMake builds

---

# Dependencies


| Dependency   | Version             |
| -------------- | --------------------- |
| C++ Standard | C++17               |
| CMake        | 3.15 or newer       |
| Crypto++     | 8.x or newer        |
| GCC (Ubuntu) | 9+ recommended      |
| MSVC         | Visual Studio 2017+ |
| MinGW-w64    | GCC 9+ recommended  |

### External Dependency

Crypto++ must be available under:

```text
external/
└── cryptopp/
    ├── include/
    └── lib/
        ├── libcryptopp.a (for MSYS2 / Linux)
        └── cryptopp.lib (for MSVC)
```

Expected library names:

#### Linux

```text
libcryptopp.a
```

or

```text
libcryptopp.so
```

#### Windows

```text
cryptopp.lib
```

or

```text
libcryptopp.a
```

---

# Build Requirements

The project:

* Uses CMake
* Supports out-of-source builds
* Must compile on:

  * Ubuntu LTS
  * Windows (MSVC)
  * Windows (MinGW64)

Required build workflow:

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

# Build Commands

## Linux

```bash
mkdir build
cd build

cmake ..
cmake --build .
```

Executable:

```text
build\aestool.exe
```

## Windows (MSVC)

```cmd
mkdir build
cd build

cmake ..
cmake --build . --config Release
```

Executable:

```text
build\Release\aestool.exe
```

## Windows (MSYS2 / MinGW)

```cmd
mkdir build
cd build

cmake .. -G "MinGW Makefiles"
cmake --build .
```

Executable:

```text
build\aestool.exe
```

---
# Python GUI

The GUI is implemented in `gui_qt.py` using PyQt6 and `ctypes`. It auto-discovers the built shared library (`cryptocore.dll` on Windows, `libcryptocore.so` on Linux) on startup.

## Requirements

### Windows / Linux (Ubuntu LTS)
```bash
pip install PyQt6
```

## Running the GUI

```bash
python gui_qt.py
```

The GUI will:
1. Automatically search for the compiled shared library (`*.dll` / `*.so`) in the `build/` directory.
2. Load the library and configure the AES C-wrapper functions.
3. Print a success status in the log console at the bottom.

## Custom Library Path

If the shared library is in a non-standard location:
1. Go to the **Core Library Configuration** card on the left panel.
2. Click **Browse DLL** → select your `.dll` or `.so` file.
3. Click **Load DLL** → the library is reloaded dynamically.

## DLL Runtime Dependencies (Windows)

On Windows, the compiled library may require MinGW runtime DLLs. If a loading error occurs, ensure your MinGW/MSYS2 bin directory is added to your environment `PATH`:

```powershell
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
python gui_qt.py
```

Or permanently add `C:\msys64\mingw64\bin` to your system environment variables.

---

# Example CLI Usage

## Show Help

```bash
aestool --help
```

## Encrypt Text (GCM)

```bash
aestool encrypt \
  --mode gcm \
  --text "Confidential Data" \
  --key-hex 00112233445566778899AABBCCDDEEFF \
  --iv 00112233445566778899AABB \
  --aead
```

## Encrypt File (CBC)

```bash
aestool encrypt \
  --mode cbc \
  --in plaintext.bin \
  --out ciphertext.bin \
  --key-hex 00112233445566778899AABBCCDDEEFF \
  --iv 0102030405060708090A0B0C0D0E0F10
```

## Decrypt File

```bash
aestool decrypt \
  --mode cbc \
  --in ciphertext.bin \
  --out recovered.bin \
  --key-hex 00112233445566778899AABBCCDDEEFF \
  --iv 0102030405060708090A0B0C0D0E0F10
```

## Base64 Output

```bash
aestool encrypt \
  --mode ctr \
  --text "Hello World" \
  --encode base64
```

## Run NIST KAT Tests

```bash
aestool --kat SampleData/vectors.json
```

## Verbose Mode

```bash
aestool encrypt \
  --mode gcm \
  --text "secret" \
  --verbose
```

---

# Unit Tests

Unit tests use [Catch2 v3](https://github.com/catchorg/Catch2) fetched automatically via CMake `FetchContent` on first configure.

## Build and run tests

```bash
# Configure (downloads Catch2 automatically)
mkdir build && cd build
cmake ..

# Build tests
cmake --build . --target aestool_tests

# Run all tests via ctest
ctest --output-on-failure
```

## Test coverage

* **CBC** — Encrypt → Decrypt round-trip correctness
* **ECB** — Fail-closed on > 16 KiB without `--allow-ecb`; pass with override
* **GCM** — AEAD positive path; tampered ciphertext fails; tampered tag fails; wrong key fails
* **IV length** — Invalid IV length rejected before any cryptographic operation

---

# Project Structure

```text
.
├── CMakeLists.txt
├── include/
│   └── nlohmann/
│       └── json.hpp
├── src/
│   ├── main.cpp
│   ├── crypto_engine.cpp
│   ├── crypto_engine.hpp
│   ├── utils.cpp
│   ├── utils.hpp
│   └── tests.cpp          ← Catch2 unit tests
├── SampleData/
│   └── vectors.json
└── build/
```

---

# Misuse Prevention

## ECB Restrictions

When `--mode ecb` is selected:

* A `[WARNING]` is printed to stderr on both encrypt and decrypt.
* Inputs larger than **16 KiB** are rejected unless `--allow-ecb` is supplied.
* All rejections fail closed (non-zero exit, no output file written).

## IV / Nonce Handling

Per-mode IV length enforcement:

| Mode | IV length |
|------|-----------|
| CBC, CTR, OFB, CFB, XTS | 16 bytes |
| GCM | 12 bytes |
| CCM | 7–13 bytes |
| ECB | not used |

If IV/nonce is omitted (except ECB):

* A cryptographically secure value is generated via Crypto++ `AutoSeededRandomPool`.
* The IV is persisted to the sidecar JSON (`<out>.json`) when `--out` is used.
* When printing to stdout, `[IV-HEX]:` is emitted after the ciphertext.

IV/nonce may be supplied as:

* `--iv <file>` / `--nonce <file>` — raw binary file or hex-encoded file with header (`# HEX …`, `HEX:…`)
* Inline hex string (when the path does not exist as a file)

Invalid IV lengths are rejected before any cryptographic operation.

## Nonce Reuse Protection (CTR, GCM, CCM)

Before each encryption with CTR, GCM, or CCM, the engine checks whether the `(key, nonce)` pair was previously used.

**Detection logic:**

1. Build a token: `hex(key) + "||" + hex(nonce)`.
2. Compare against an in-process registry loaded at first check.
3. Also load entries from `.aestool_nonce_registry.json` in the working directory (written by prior encrypt operations).
4. If a match is found → reject with `CRITICAL SECURITY VIOLATION: Detected reuse of (Key, Nonce) pair!`
5. After a successful encrypt, register the pair in memory and append to `.aestool_nonce_registry.json`.

Sidecar JSON headers record the IV/nonce used for each ciphertext, enabling verification that unique nonces were employed per key.

## Key File Formats

`--key KEYFILE` accepts:

* **Raw binary** — e.g. a 32-byte AES-256 key file
* **Hex-encoded with header** — lines starting with `#` or `HEX:` followed by hex digits

`--key-hex HEXSTRING` accepts inline hex directly.

---

# Sidecar JSON Header

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

On decrypt, metadata is auto-loaded from `<in>.json` when present.

---

# Known Answer Tests (KAT)

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

---

# Known Limitations

1. Building the project requires an active internet connection during the first CMake configuration if Crypto++ is fetched automatically.
2. Initial configuration may take longer because third-party dependencies are built as part of the project.
3. Multi-threading configuration (`--threads`) is parsed by the CLI but may not provide performance improvements for every cipher mode.
4. XTS mode requires either a 32-byte or 64-byte key.
5. GCM expects a 12-byte IV.
6. CCM accepts IV lengths between 7 and 13 bytes.
7. ECB mode is intentionally restricted for large inputs unless `--allow-ecb` is explicitly supplied.
8. The repository does not currently include automated package management (vcpkg, Conan, FetchContent, CPM, etc.).

---

# License

This project is provided for educational and laboratory purposes.

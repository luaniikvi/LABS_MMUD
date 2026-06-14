# Cryptography & Applications — Laboratory Series (Labs 1–6)

This repository contains the comprehensive implementations for Labs 1-6.

## Labs Implemented

- **Lab 1**: Symmetric Encryption with Crypto++ (AES modes: ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM)
- **Lab 3**: RSA-OAEP & Hybrid Encryption (RSA-3072/4096 + AES-256-GCM envelope encryption)

## Dependencies
- Modern C++ (C++17 or later)
- CMake 3.15+
- Crypto++
- Catch2 (Fetched automatically via CMake)

## Build Instructions

This project enforces out-of-source builds.

### Windows (MSVC)
```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Linux (Ubuntu LTS)
```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Running Tests
After building, you can run all unit tests using CTest:
```bash
cd build
ctest -C Release -V
```

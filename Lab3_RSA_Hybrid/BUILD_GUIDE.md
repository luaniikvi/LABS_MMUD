# Lab 3 - Build Guide

This guide explains how to build Lab 3 with different compilers.

## Supported Compilers

- ✅ **MSVC** - Windows
- ✅ **MinGW** (MSYS2) - Windows
- ✅ **GCC** - Linux

## Quick Build

### Windows - PowerShell (MSVC - Default)

```powershell
.\build_lab3.ps1
```

### Windows - PowerShell (MinGW/MSYS2)

```powershell
.\build_lab3.ps1 -Compiler mingw
```

### Manual Build - MSVC

```cmd
cd Lab3_RSA_Hybrid
mkdir build_msvc && cd build_msvc
cmake ..
cmake --build . --config Release
ctest -C Release -V
```

### Manual Build - MinGW (MSYS2)

Open MSYS2 MinGW64 terminal:

```bash
cd Lab3_RSA_Hybrid
mkdir build_mingw && cd build_mingw
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build .
ctest -V
```

### Manual Build - Linux

```bash
cd Lab3_RSA_Hybrid
mkdir build && cd build
cmake ..
cmake --build .
ctest -V
```

## Compiler Detection

The CMakeLists.txt automatically detects your compiler:

```
-- [Lab3] Compiling with MSVC
-- [Lab3] Found Crypto++ (MSVC): ../external/cryptopp/lib/Release/cryptlib.lib

-- [Lab3] Compiling with MinGW (MSYS2)
-- [Lab3] Found Crypto++ (MinGW/Linux): ../external/cryptopp/libcryptopp.a

-- [Lab3] Compiling with GCC/Clang
-- [Lab3] Found Crypto++: ../external/cryptopp/libcryptopp.a
```

## Crypto++ Library Paths

### MSVC
```
external/cryptopp/
├── lib/
│   ├── Release/
│   │   └── cryptlib.lib
│   └── Debug/
│       └── cryptlib.lib
└── include/
```

### MinGW/Linux
```
external/cryptopp/
├── libcryptopp.a          (or lib/libcryptopp.a)
└── include/
```

## Build Outputs

### MSVC
```
Lab3_RSA_Hybrid/build_msvc/
└── Release/
    ├── rsatool.exe
    ├── test_lab3.exe
    └── benchmark_lab3.exe
```

### MinGW/Linux
```
Lab3_RSA_Hybrid/build_mingw/
├── rsatool.exe            (or rsatool on Linux)
├── test_lab3.exe          (or test_lab3 on Linux)
└── benchmark_lab3.exe     (or benchmark_lab3 on Linux)
```

## Compiler Flags

### MSVC
- `/W4` - Warning level 4
- `/WX-` - Warnings are not errors
- `MultiThreaded` runtime (static linking)

### GCC/Clang/MinGW
- `-Wall` - All common warnings
- `-Wextra` - Extra warnings
- `-pedantic` - Strict ISO C++ compliance
- `-Wno-unused-parameter` - Suppress unused parameter warnings

## Troubleshooting

### Error: Crypto++ library not found

**MSVC:**
```
[Lab3] Crypto++ library not found at ../external/cryptopp/lib/Release/cryptlib.lib
Please build Crypto++ first for MSVC.
```

**Solution:**
```cmd
cd external\cryptopp
nmake /f vcryptopp.vcproj
```

**MinGW:**
```
[Lab3] Crypto++ library not found at ../external/cryptopp/libcryptopp.a
Please build Crypto++ first for MinGW/MSYS2.
```

**Solution (MSYS2):**
```bash
cd external/cryptopp
make -f GNUmakefile
```

### Error: CMake generator not found

**MSVC:**
```
CMake Error: Could not create named generator Visual Studio 17 2022
```

**Solution:** Install Visual Studio 2022 with C++ desktop development workload.

**MinGW:**
```
CMake Error: Could not create named generator MinGW Makefiles
```

**Solution:** Run CMake from MSYS2 MinGW64 terminal, not from CMD/PowerShell.

### Error: Catch2 not found

The Catch2 amalgamation should be in `Lab3_RSA_Hybrid/include/catch2/`. If missing:

```powershell
Copy-Item "Lab1_Symmetric\include\catch2\*" "Lab3_RSA_Hybrid\include\catch2\" -Force
```

## Testing

After building, run tests:

```powershell
# MSVC
cd build_msvc
ctest -C Release -V

# MinGW
cd build_mingw
ctest -V
```

## Benchmarking

```powershell
# MSVC
.\build_msvc\Release\benchmark_lab3.exe

# MinGW
.\build_mingw\benchmark_lab3.exe
```

## Clean Build

To start fresh:

```powershell
# Remove all build directories
Remove-Item -Recurse -Force build_msvc, build_mingw

# Rebuild with MSVC
.\build_lab3.ps1 -Compiler msvc

# Rebuild with MinGW
.\build_lab3.ps1 -Compiler mingw
```

## Cross-Platform Notes

### Windows (MSVC)
- Uses `.lib` static libraries
- Multi-config generator (Debug/Release in same build)
- Executables in `Release/` or `Debug/` subdirectories

### Windows (MinGW)
- Uses `.a` static libraries
- Single-config generator (specify at configure time)
- Executables in build root

### Linux (GCC)
- Uses `.a` static libraries
- Same as MinGW build process
- Executables may not have `.exe` extension

## CMake Variables

You can override these variables if needed:

```bash
# Specify Crypto++ path
cmake .. -DCRYPTOPP_ROOT=/path/to/cryptopp

# Specify C++ compiler
cmake .. -DCMAKE_CXX_COMPILER=g++

# Build type (for single-config generators)
cmake .. -DCMAKE_BUILD_TYPE=Release
```

## Verification

After successful build, verify:

```powershell
# Check executables exist
Test-Path build_msvc\Release\rsatool.exe      # MSVC
Test-Path build_mingw\rsatool.exe              # MinGW

# Run quick test
.\build_msvc\Release\rsatool.exe --help
.\build_mingw\rsatool.exe --help
```

Expected output:
```
Usage: rsatool <command> [options]

Commands:
  keygen     Generate RSA key pair
  encrypt    Encrypt (RSA-OAEP or hybrid)
  decrypt    Decrypt (RSA-OAEP or hybrid)
  kat        Run Known Answer Tests
```

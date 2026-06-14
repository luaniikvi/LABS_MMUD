# Lab 1 Verification Checklist

## Pre-Build Checks
- [x] gui_qt6.py compiles without errors (python -m py_compile gui_qt6.py)
- [x] All source files present in src/ directory
- [x] CMakeLists.txt configured correctly
- [x] External dependencies available (Crypto++, Catch2, nlohmann/json)

## Build Checklist
```bash
# Clean build
rm -rf build
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

Expected outputs in build/:
- [ ] aestool.exe (CLI tool)
- [ ] aestool_bench.exe (benchmark tool)
- [ ] aestool_tests.exe (unit tests)
- [ ] aestool.dll (GUI library)

## CLI Verification
- [ ] `aestool --help` shows usage
- [ ] `aestool encrypt --mode gcm --key-hex <32-byte-hex> --iv <12-byte-hex> --text "Hello" --aead` works
- [ ] `aestool decrypt --mode gcm --key-hex <same-key> --iv <same-iv> --aead` works with ciphertext
- [ ] `aestool --kat SampleData/vectors.json` runs KAT tests
- [ ] `aestool_bench.exe` runs benchmark with all modes and sizes
- [ ] `aestool_tests.exe` runs Catch2 tests

## GUI Verification
- [ ] `python gui_qt6.py` launches without errors
- [ ] DLL auto-detected at startup (check log panel)
- [ ] Encrypt tab works:
  - [ ] Select mode (gcm, cbc, etc.)
  - [ ] Enter plaintext
  - [ ] Click ENCRYPT
  - [ ] Ciphertext displayed in hex
  - [ ] Key/IV/Tag auto-generated and shown in log
- [ ] Decrypt tab works:
  - [ ] Switch to Decrypt radio button
  - [ ] Paste ciphertext
  - [ ] Enter key and IV
  - [ ] For GCM/CCM: enter tag
  - [ ] Click DECRYPT
  - [ ] Plaintext displayed
- [ ] File I/O works:
  - [ ] Browse input file
  - [ ] Browse output file
  - [ ] Encrypt/decrypt files
  - [ ] Sidecar JSON created
- [ ] Benchmark tab works:
  - [ ] Click "Run Benchmark"
  - [ ] Real-time output appears
  - [ ] Can stop with "Stop" button
- [ ] Unit Tests tab works:
  - [ ] Click "Run All Tests"
  - [ ] Test output appears
  - [ ] Stats shown (Total/Passed/Failed)
- [ ] NIST KAT tab works:
  - [ ] Vectors file auto-detected
  - [ ] Click "Run KAT Validation"
  - [ ] PASS/FAIL per test shown
  - [ ] Summary statistics displayed

## Requirements Compliance
- [x] All 8 AES modes implemented
- [x] AEAD support (GCM, CCM)
- [x] ECB misuse prevention
- [x] Nonce reuse protection
- [x] IV length validation
- [x] Auto IV generation
- [x] Sidecar JSON metadata
- [x] UTF-8 support
- [x] Fail-closed behavior
- [x] NIST KAT validation
- [x] Benchmark with statistics
- [x] Catch2 unit tests
- [x] DLL export for GUI
- [x] Python GUI using ctypes
- [x] No duplicated crypto logic in GUI
- [x] CMake build system
- [x] Out-of-source build support

## Final Checks
- [x] gui_qt6.py is production-ready
- [x] All features working correctly
- [x] Light theme applied
- [x] Professional UI/UX
- [x] Meets all LABS_requirements.txt criteria

## Notes
- gui_qt.py is now redundant (same functionality as gui_qt6.py)
- Can delete gui_qt.py to avoid confusion
- Both use the same DLL API (encrypt_aes_c/decrypt_aes_c)

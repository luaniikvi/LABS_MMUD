cmake_minimum_required(VERSION 3.15)

project(Lab4_Hash_PKI LANGUAGES CXX)

# C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enforce out-of-source builds
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source build is not supported.\n"
        "Please use:\n"
        "mkdir build\n"
        "cd build\n"
        "cmake .."
    )
endif()

# ------------------------------------------------------------------------------
# Compiler Detection & Configuration
# ------------------------------------------------------------------------------
if(MSVC)
    message(STATUS "[Lab4] Compiling with MSVC")
    set(COMPILER_NAME "msvc")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
elseif(MINGW)
    message(STATUS "[Lab4] Compiling with MinGW (MSYS2)")
    set(COMPILER_NAME "mingw")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static -lpthread")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static -lpthread")
    get_filename_component(MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    message(STATUS "[Lab4] MinGW bin dir: ${MINGW_BIN_DIR}")
else()
    message(STATUS "[Lab4] Compiling with GCC/Clang")
    set(COMPILER_NAME "gcc")
endif()

# ------------------------------------------------------------------------------
# Catch2 — local amalgamation
# ------------------------------------------------------------------------------
if(NOT TARGET Catch2::Catch2WithMain)
    set(CATCH2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/catch2")
    add_library(Catch2WithMain_lab4 STATIC
        "${CATCH2_DIR}/catch_amalgamated.cpp"
    )
    target_include_directories(Catch2WithMain_lab4 PUBLIC "${CATCH2_DIR}")
    target_compile_features(Catch2WithMain_lab4 PUBLIC cxx_std_17)
    add_library(Catch2::Catch2WithMain ALIAS Catch2WithMain_lab4)
endif()

# ------------------------------------------------------------------------------
# Crypto++
# ------------------------------------------------------------------------------
set(CRYPTOPP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../external/cryptopp")
set(CRYPTOPP_INCLUDE_DIR "${CRYPTOPP_ROOT}/include")

if(MSVC)
    set(CRYPTOPP_LIB_RELEASE "${CRYPTOPP_ROOT}/lib/cryptopp.lib")
    set(CRYPTOPP_LIB_DEBUG "${CRYPTOPP_ROOT}/lib/cryptopp.lib")
    if(EXISTS "${CRYPTOPP_LIB_RELEASE}")
        set(CRYPTOPP_LIB optimized "${CRYPTOPP_LIB_RELEASE}" debug "${CRYPTOPP_LIB_DEBUG}")
        message(STATUS "[Lab4] Found Crypto++ (MSVC): ${CRYPTOPP_LIB_RELEASE}")
    else()
        message(FATAL_ERROR "[Lab4] Crypto++ library not found at ${CRYPTOPP_LIB_RELEASE}")
    endif()
elseif(MINGW OR CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    set(CRYPTOPP_LIB "${CRYPTOPP_ROOT}/libcryptopp.a")
    if(NOT EXISTS "${CRYPTOPP_LIB}")
        set(CRYPTOPP_LIB "${CRYPTOPP_ROOT}/lib/libcryptopp.a")
    endif()
    if(EXISTS "${CRYPTOPP_LIB}")
        message(STATUS "[Lab4] Found Crypto++ (MinGW/Linux): ${CRYPTOPP_LIB}")
    else()
        message(FATAL_ERROR "[Lab4] Crypto++ library not found at ${CRYPTOPP_LIB}")
    endif()
else()
    find_library(CRYPTOPP_LIB NAMES cryptopp libcryptopp
        PATHS "${CRYPTOPP_ROOT}/lib" "${CRYPTOPP_ROOT}" NO_DEFAULT_PATH)
    if(NOT CRYPTOPP_LIB)
        message(FATAL_ERROR "[Lab4] Crypto++ library not found in ${CRYPTOPP_ROOT}")
    endif()
    message(STATUS "[Lab4] Found Crypto++: ${CRYPTOPP_LIB}")
endif()

# ------------------------------------------------------------------------------
# OpenSSL (for X.509 parsing)
# ------------------------------------------------------------------------------
set(OPENSSL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../external/openssl")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT}/include")

if(MSVC)
    set(OPENSSL_CRYPTO_LIB "${OPENSSL_ROOT}/lib64/libcrypto_static.lib")
    if(EXISTS "${OPENSSL_CRYPTO_LIB}")
        message(STATUS "[Lab4] Found OpenSSL (MSVC): ${OPENSSL_CRYPTO_LIB}")
    else()
        message(FATAL_ERROR "[Lab4] OpenSSL libcrypto not found at ${OPENSSL_CRYPTO_LIB}")
    endif()
elseif(MINGW)
    set(OPENSSL_CRYPTO_LIB "${OPENSSL_ROOT}/lib64/libcrypto.a")
    if(EXISTS "${OPENSSL_CRYPTO_LIB}")
        message(STATUS "[Lab4] Found OpenSSL (MinGW): ${OPENSSL_CRYPTO_LIB}")
    else()
        message(FATAL_ERROR "[Lab4] OpenSSL libcrypto not found at ${OPENSSL_CRYPTO_LIB}")
    endif()
else()
    find_library(OPENSSL_CRYPTO_LIB NAMES crypto libcrypto
        PATHS "${OPENSSL_ROOT}/lib64" "${OPENSSL_ROOT}/lib" NO_DEFAULT_PATH)
    if(NOT OPENSSL_CRYPTO_LIB)
        message(FATAL_ERROR "[Lab4] OpenSSL libcrypto not found")
    endif()
    message(STATUS "[Lab4] Found OpenSSL: ${OPENSSL_CRYPTO_LIB}")
endif()

# Windows-specific libraries needed by OpenSSL
if(WIN32)
    set(OPENSSL_EXTRA_LIBS ws2_32 crypt32 advapi32 user32)
else()
    set(OPENSSL_EXTRA_LIBS dl pthread)
endif()

# Common include directories
set(COMMON_INCLUDES
    ${CRYPTOPP_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# Common link libraries
set(COMMON_LIBS
    ${CRYPTOPP_LIB}
    ${OPENSSL_CRYPTO_LIB}
    ${OPENSSL_EXTRA_LIBS}
)

# Common source files
set(COMMON_SOURCES
    src/hash_engine.cpp
    src/x509_parser.cpp
    src/length_ext.cpp
    src/utils.cpp
)

# Suppress MSVC deprecation warnings for fopen, strncpy, etc.
if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# OpenSSL static lib imports __imp_* CRT symbols (built with /MD).
# Force linker to resolve these from ucrt at runtime; /FORCE:MULTIPLE
# suppresses duplicate symbol errors from mixing static/dynamic CRT.
if(MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /FORCE:MULTIPLE")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /FORCE:MULTIPLE")
    list(APPEND OPENSSL_EXTRA_LIBS ucrt vcruntime)
endif()

# ------------------------------------------------------------------------------
# hashtool executable
# ------------------------------------------------------------------------------
add_executable(hashtool
    src/main.cpp
    ${COMMON_SOURCES}
)

target_include_directories(hashtool PRIVATE ${COMMON_INCLUDES})
target_link_libraries(hashtool PRIVATE ${COMMON_LIBS})

if(MSVC)
    target_compile_options(hashtool PRIVATE /W4 /WX-)
    target_link_options(hashtool PRIVATE /FORCE:MULTIPLE)
    set_property(TARGET hashtool APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(hashtool PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------
add_executable(catch2_test
    src/tests.cpp
    ${COMMON_SOURCES}
)

target_include_directories(catch2_test PRIVATE ${COMMON_INCLUDES})
target_link_libraries(catch2_test PRIVATE ${COMMON_LIBS} Catch2::Catch2WithMain)

if(MSVC)
    target_compile_options(catch2_test PRIVATE /W4 /WX-)
    target_link_options(catch2_test PRIVATE /FORCE:MULTIPLE)
    set_property(TARGET catch2_test APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(catch2_test PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

enable_testing()
add_test(NAME Lab4_Tests COMMAND catch2_test WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

# ------------------------------------------------------------------------------
# Benchmark executable
# ------------------------------------------------------------------------------
add_executable(benchmark
    src/benchmark_main.cpp
    src/benchmark.cpp
    src/hash_engine.cpp
    src/utils.cpp
)

target_include_directories(benchmark PRIVATE ${COMMON_INCLUDES})
target_link_libraries(benchmark PRIVATE ${COMMON_LIBS})

if(MSVC)
    target_compile_options(benchmark PRIVATE /W4 /WX-)
    target_link_options(benchmark PRIVATE /FORCE:MULTIPLE)
    set_property(TARGET benchmark APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE")
    # Compiler optimizations for benchmark
    target_compile_options(benchmark PRIVATE /O2 /Oi /Ot /GL)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(benchmark PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
    target_compile_options(benchmark PRIVATE -O3 -march=native -mtune=native)
endif()

# ------------------------------------------------------------------------------
# DLL Library for Python GUI
# ------------------------------------------------------------------------------
add_library(hashtool_lib SHARED
    src/dll_wrapper.cpp
    ${COMMON_SOURCES}
)

target_include_directories(hashtool_lib PRIVATE ${COMMON_INCLUDES})
target_link_libraries(hashtool_lib PRIVATE ${COMMON_LIBS})

target_compile_definitions(hashtool_lib PRIVATE BUILDING_DLL)

if(MSVC)
    target_compile_options(hashtool_lib PRIVATE /W4)
    target_link_options(hashtool_lib PRIVATE /FORCE:MULTIPLE)
    set_property(TARGET hashtool_lib APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE")
else()
    target_compile_options(hashtool_lib PRIVATE -Wall -Wextra -pedantic)
endif()

set_target_properties(hashtool_lib PROPERTIES
    OUTPUT_NAME "hashtool"
    PREFIX ""
)

# ------------------------------------------------------------------------------
# Post-build auto-copy runtime DLLs (MinGW only, not MSVC)
# ------------------------------------------------------------------------------
if(NOT MSVC)
    get_filename_component(MINGW_RUNTIME_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    if(NOT EXISTS "${MINGW_RUNTIME_DIR}/libstdc++-6.dll")
        if(EXISTS "C:/msys64/mingw64/bin/libstdc++-6.dll")
            set(MINGW_RUNTIME_DIR "C:/msys64/mingw64/bin")
        endif()
    endif()
    message(STATUS "[Lab4] MinGW runtime DLL dir: ${MINGW_RUNTIME_DIR}")

    set(MINGW_RUNTIME_DLLS
        "libgcc_s_seh-1.dll"
        "libstdc++-6.dll"
        "libwinpthread-1.dll"
    )

    foreach(_target hashtool catch2_test benchmark hashtool_lib)
        foreach(_dll ${MINGW_RUNTIME_DLLS})
            add_custom_command(TARGET ${_target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${MINGW_RUNTIME_DIR}/${_dll}"
                    "$<TARGET_FILE_DIR:${_target}>/${_dll}"
            )
        endforeach()
    endforeach()
endif()

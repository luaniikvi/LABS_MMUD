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
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
elseif(MINGW)
    message(STATUS "[Lab4] Compiling with MinGW (MSYS2)")
    set(COMPILER_NAME "mingw")
    # Statically link MinGW runtime so no libgcc/libstdc++/libwinpthread DLLs needed
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static -lpthread")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static -lpthread")
    
    # Find MinGW bin directory for DLL fallback copy
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
    set(CATCH2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
    add_library(Catch2WithMain_lab4 STATIC
        "${CATCH2_DIR}/catch2/catch_amalgamated.cpp"
    )
    target_include_directories(Catch2WithMain_lab4 PUBLIC "${CATCH2_DIR}")
    target_compile_features(Catch2WithMain_lab4 PUBLIC cxx_std_17)
    
    if(MSVC)
        set_target_properties(Catch2WithMain_lab4 PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        )
    endif()
    
    add_library(Catch2::Catch2WithMain ALIAS Catch2WithMain_lab4)
endif()

# ------------------------------------------------------------------------------
# Crypto++ Dependency
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
    find_library(CRYPTOPP_LIB
        NAMES cryptopp libcryptopp
        PATHS "${CRYPTOPP_ROOT}/lib" "${CRYPTOPP_ROOT}"
        NO_DEFAULT_PATH
    )
    if(NOT CRYPTOPP_LIB)
        message(FATAL_ERROR "[Lab4] Crypto++ library not found in ${CRYPTOPP_ROOT}")
    endif()
    message(STATUS "[Lab4] Found Crypto++: ${CRYPTOPP_LIB}")
endif()

# ------------------------------------------------------------------------------
# OpenSSL Dependency
# ------------------------------------------------------------------------------
set(OPENSSL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../external/openssl")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT}/include")

if(MSVC)
    set(OPENSSL_CRYPTO_LIB "${OPENSSL_ROOT}/lib64/libcrypto_static.lib")
    set(OPENSSL_SSL_LIB "${OPENSSL_ROOT}/lib64/libssl_static.lib")
    if(EXISTS "${OPENSSL_CRYPTO_LIB}")
        set(OPENSSL_LIBS "${OPENSSL_CRYPTO_LIB}" "${OPENSSL_SSL_LIB}")
        message(STATUS "[Lab4] Found OpenSSL (MSVC): ${OPENSSL_CRYPTO_LIB}")
    else()
        message(FATAL_ERROR "[Lab4] OpenSSL library not found at ${OPENSSL_CRYPTO_LIB}")
    endif()
elseif(MINGW OR CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    set(OPENSSL_CRYPTO_LIB "${OPENSSL_ROOT}/lib64/libcrypto.a")
    set(OPENSSL_SSL_LIB "${OPENSSL_ROOT}/lib64/libssl.a")
    if(EXISTS "${OPENSSL_CRYPTO_LIB}")
        set(OPENSSL_LIBS "${OPENSSL_CRYPTO_LIB}" "${OPENSSL_SSL_LIB}")
        message(STATUS "[Lab4] Found OpenSSL (MinGW/Linux): ${OPENSSL_CRYPTO_LIB}")
    else()
        message(FATAL_ERROR "[Lab4] OpenSSL library not found at ${OPENSSL_CRYPTO_LIB}")
    endif()
else()
    find_library(OPENSSL_CRYPTO_LIB NAMES crypto PATHS "${OPENSSL_ROOT}/lib64" "${OPENSSL_ROOT}/lib" NO_DEFAULT_PATH)
    find_library(OPENSSL_SSL_LIB NAMES ssl PATHS "${OPENSSL_ROOT}/lib64" "${OPENSSL_ROOT}/lib" NO_DEFAULT_PATH)
    if(NOT OPENSSL_CRYPTO_LIB)
        message(FATAL_ERROR "[Lab4] OpenSSL crypto library not found in ${OPENSSL_ROOT}")
    endif()
    set(OPENSSL_LIBS "${OPENSSL_CRYPTO_LIB}" "${OPENSSL_SSL_LIB}")
    message(STATUS "[Lab4] Found OpenSSL: ${OPENSSL_CRYPTO_LIB}")
endif()

if(MSVC)
    # Static OpenSSL on MSVC pulls in Winsock/Crypto APIs plus legacy stdio names
    list(APPEND OPENSSL_LIBS ws2_32 crypt32 wintrust advapi32 legacy_stdio_definitions.lib)
endif()

# Threads package
find_package(Threads REQUIRED)

# ------------------------------------------------------------------------------
# hashtool executable
# ------------------------------------------------------------------------------
add_executable(hashtool
    src/main.cpp
    src/hash_engine.cpp
    src/hash_engine.hpp
    src/x509_parser.cpp
    src/x509_parser.hpp
    src/length_ext.cpp
    src/length_ext.hpp
    src/utils.cpp
    src/utils.hpp
    src/applink.c
)

target_include_directories(hashtool PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(hashtool PRIVATE
    ${CRYPTOPP_LIB}
    ${OPENSSL_LIBS}
    Threads::Threads
)

# Compiler-specific warning flags
if(MSVC)
    target_compile_options(hashtool PRIVATE /W4 /WX-)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(hashtool PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

install(TARGETS hashtool RUNTIME DESTINATION bin)

# ------------------------------------------------------------------------------
# catch2_test executable
# ------------------------------------------------------------------------------
add_executable(catch2_test
    src/tests.cpp
    src/hash_engine.cpp
    src/hash_engine.hpp
    src/x509_parser.cpp
    src/x509_parser.hpp
    src/length_ext.cpp
    src/length_ext.hpp
    src/utils.cpp
    src/utils.hpp
    src/applink.c
)

target_include_directories(catch2_test PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(catch2_test PRIVATE
    ${CRYPTOPP_LIB}
    ${OPENSSL_LIBS}
    Catch2::Catch2WithMain
    Threads::Threads
)

if(MSVC)
    target_compile_options(catch2_test PRIVATE /W4 /WX-)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(catch2_test PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

# Register tests with CTest
add_test(NAME Lab4_Tests COMMAND catch2_test WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

# ------------------------------------------------------------------------------
# benchmark executable
# ------------------------------------------------------------------------------
add_executable(benchmark
    src/benchmark_main.cpp
    src/benchmark.cpp
    src/benchmark.hpp
    src/hash_engine.cpp
    src/hash_engine.hpp
    src/utils.cpp
    src/utils.hpp
)

target_include_directories(benchmark PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(benchmark PRIVATE
    ${CRYPTOPP_LIB}
    Threads::Threads
)

# Optimization flags for benchmark
if(MSVC)
    target_compile_options(benchmark PRIVATE /O2 /Oi /Ot /GL)
    target_link_options(benchmark PRIVATE /LTCG)
else()
    target_compile_options(benchmark PRIVATE -O3 -march=native -mtune=native)
    target_link_options(benchmark PRIVATE -flto)
endif()

if(MSVC)
    target_compile_options(benchmark PRIVATE /W4 /WX-)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(benchmark PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

install(TARGETS benchmark RUNTIME DESTINATION bin)

# ------------------------------------------------------------------------------
# DLL Library for Python GUI (hashtool_lib)
# ------------------------------------------------------------------------------
add_library(hashtool_lib SHARED
    src/dll_wrapper.cpp
    src/hash_engine.cpp
    src/x509_parser.cpp
    src/length_ext.cpp
    src/utils.cpp
    src/applink.c
)

target_include_directories(hashtool_lib PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(hashtool_lib PRIVATE
    ${CRYPTOPP_LIB}
    ${OPENSSL_LIBS}
    Threads::Threads
)

target_compile_definitions(hashtool_lib PRIVATE BUILDING_DLL)

if(MSVC)
    target_compile_options(hashtool_lib PRIVATE /W4)
else()
    target_compile_options(hashtool_lib PRIVATE -Wall -Wextra -pedantic)
endif()

set_target_properties(hashtool_lib PROPERTIES
    OUTPUT_NAME "hashtool"
    PREFIX ""
)

# ------------------------------------------------------------------------------
# MinGW: Post-build auto-copy runtime DLLs to build directory
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

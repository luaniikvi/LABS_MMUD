cmake_minimum_required(VERSION 3.15)

project(Lab6_PQC LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source build not supported. Use: mkdir build && cd build && cmake ..")
endif()

if(MSVC)
    message(STATUS "[Lab6] Compiling with MSVC")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
elseif(MINGW OR CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_HOST_SYSTEM_NAME STREQUAL "MSYS")
    message(STATUS "[Lab6] Compiling with MinGW")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -Wl,--temp-prefix,/tmp/ -lpthread")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -Wl,--temp-prefix,/tmp/ -lpthread")
else()
    message(STATUS "[Lab6] Compiling with GCC/Clang")
endif()

# Catch2
if(NOT TARGET Catch2::Catch2WithMain)
    set(CATCH2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
    add_library(Catch2WithMain_lab6 STATIC "${CATCH2_DIR}/catch2/catch_amalgamated.cpp")
    target_include_directories(Catch2WithMain_lab6 PUBLIC "${CATCH2_DIR}")
    target_compile_features(Catch2WithMain_lab6 PUBLIC cxx_std_17)
    if(MSVC)
        set_target_properties(Catch2WithMain_lab6 PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()
    add_library(Catch2::Catch2WithMain ALIAS Catch2WithMain_lab6)
endif()

# Crypto++ (for SHA hashing only)
set(CRYPTOPP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../external/cryptopp")
set(CRYPTOPP_INCLUDE_DIR "${CRYPTOPP_ROOT}/include")
if(MSVC)
    set(CRYPTOPP_LIB_RELEASE "${CRYPTOPP_ROOT}/lib/cryptopp.lib")
    if(EXISTS "${CRYPTOPP_LIB_RELEASE}")
        set(CRYPTOPP_LIB optimized "${CRYPTOPP_LIB_RELEASE}" debug "${CRYPTOPP_LIB_RELEASE}")
        message(STATUS "[Lab6] Found Crypto++ (MSVC): ${CRYPTOPP_LIB_RELEASE}")
    else()
        message(FATAL_ERROR "[Lab6] Crypto++ not found at ${CRYPTOPP_LIB_RELEASE}")
    endif()
elseif(MINGW OR CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_HOST_SYSTEM_NAME STREQUAL "MSYS")
    set(CRYPTOPP_LIB "${CRYPTOPP_ROOT}/libcryptopp.a")
    if(NOT EXISTS "${CRYPTOPP_LIB}")
        set(CRYPTOPP_LIB "${CRYPTOPP_ROOT}/lib/libcryptopp.a")
    endif()
    if(NOT EXISTS "${CRYPTOPP_LIB}")
        message(FATAL_ERROR "[Lab6] Crypto++ lib not found")
    endif()
endif()

# OpenSSL (for ML-DSA, ML-KEM)
set(OPENSSL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../external/openssl")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT}/include")
if(MSVC)
    set(OPENSSL_CRYPTO_LIB "${OPENSSL_ROOT}/lib64/libcrypto_static.lib")
    set(OPENSSL_SSL_LIB "${OPENSSL_ROOT}/lib64/libssl_static.lib")
    if(EXISTS "${OPENSSL_CRYPTO_LIB}")
        set(OPENSSL_LIBS "${OPENSSL_CRYPTO_LIB}" "${OPENSSL_SSL_LIB}")
    else()
        message(FATAL_ERROR "[Lab6] OpenSSL not found at ${OPENSSL_CRYPTO_LIB}")
    endif()
elseif(MINGW OR CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_HOST_SYSTEM_NAME STREQUAL "MSYS")
    set(OPENSSL_CRYPTO_LIB "${OPENSSL_ROOT}/lib64/libcrypto.a")
    set(OPENSSL_SSL_LIB "${OPENSSL_ROOT}/lib64/libssl.a")
    if(EXISTS "${OPENSSL_CRYPTO_LIB}")
        set(OPENSSL_LIBS "${OPENSSL_CRYPTO_LIB}" "${OPENSSL_SSL_LIB}")
    else()
        message(FATAL_ERROR "[Lab6] OpenSSL not found")
    endif()
endif()

if(MSVC)
    list(APPEND OPENSSL_LIBS ws2_32 crypt32 wintrust advapi32 legacy_stdio_definitions.lib)
endif()

find_package(Threads REQUIRED)

# --------------------------------------------------------------------------
# pqtool executable
# --------------------------------------------------------------------------
add_executable(pqtool
    src/main.cpp
    src/pq_engine.cpp
    src/pq_engine.hpp
    src/utils.cpp
    src/utils.hpp
    src/applink.c
)

target_include_directories(pqtool PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(pqtool PRIVATE ${CRYPTOPP_LIB} ${OPENSSL_LIBS} Threads::Threads)

if(MSVC)
    target_compile_options(pqtool PRIVATE /W4 /WX-)
else()
    target_compile_options(pqtool PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

install(TARGETS pqtool RUNTIME DESTINATION bin)

# --------------------------------------------------------------------------
# Unit Tests
# --------------------------------------------------------------------------
add_executable(catch2_test
    src/tests.cpp
    src/pq_engine.cpp
    src/pq_engine.hpp
    src/utils.cpp
    src/utils.hpp
    src/applink.c
)
target_include_directories(catch2_test PRIVATE ${CRYPTOPP_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(catch2_test PRIVATE ${CRYPTOPP_LIB} ${OPENSSL_LIBS} Catch2::Catch2WithMain Threads::Threads)
if(MSVC)
    target_compile_options(catch2_test PRIVATE /W4 /WX-)
else()
    target_compile_options(catch2_test PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()
add_test(NAME Lab6_Tests COMMAND catch2_test WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

# --------------------------------------------------------------------------
# Benchmark
# --------------------------------------------------------------------------
add_executable(benchmark
    src/benchmark_main.cpp
    src/pq_engine.cpp
    src/pq_engine.hpp
    src/utils.cpp
    src/utils.hpp
    src/benchmark.cpp
    src/applink.c
)
target_include_directories(benchmark PRIVATE ${CRYPTOPP_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(benchmark PRIVATE ${CRYPTOPP_LIB} ${OPENSSL_LIBS} Threads::Threads)
if(MSVC)
    target_compile_options(benchmark PRIVATE /O2 /Oi /Ot /GL)
    target_compile_options(benchmark PRIVATE /W4 /WX-)
    target_link_options(benchmark PRIVATE /LTCG)
else()
    target_compile_options(benchmark PRIVATE -O3 -march=native -mtune=native)
    target_compile_options(benchmark PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
    target_link_options(benchmark PRIVATE -flto)
endif()
install(TARGETS benchmark RUNTIME DESTINATION bin)

# --------------------------------------------------------------------------
# DLL Library for Python GUI
# --------------------------------------------------------------------------
add_library(pqtool_lib SHARED
    src/dll_wrapper.cpp
    src/pq_engine.cpp
    src/utils.cpp
    src/applink.c
)
target_include_directories(pqtool_lib PRIVATE ${CRYPTOPP_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(pqtool_lib PRIVATE ${CRYPTOPP_LIB} ${OPENSSL_LIBS} Threads::Threads)
target_compile_definitions(pqtool_lib PRIVATE BUILDING_DLL)
set_target_properties(pqtool_lib PROPERTIES OUTPUT_NAME "pqtool" PREFIX "")

# MinGW post-build DLL copy
if(NOT MSVC)
    get_filename_component(MINGW_RUNTIME_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    if(NOT EXISTS "${MINGW_RUNTIME_DIR}/libstdc++-6.dll" AND EXISTS "C:/msys64/mingw64/bin/libstdc++-6.dll")
        set(MINGW_RUNTIME_DIR "C:/msys64/mingw64/bin")
    endif()
    foreach(_t pqtool catch2_test benchmark pqtool_lib)
        foreach(_dll libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll)
            add_custom_command(TARGET ${_t} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${MINGW_RUNTIME_DIR}/${_dll}" "$<TARGET_FILE_DIR:${_t}>/${_dll}")
        endforeach()
    endforeach()
endif()

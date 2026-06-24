cmake_minimum_required(VERSION 3.15)

project(CryptoLab1 LANGUAGES CXX)
# C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Bắt buộc out-of-source build
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
# Catch2 — local amalgamation (installed in include/catch2/)
# ------------------------------------------------------------------------------
if(NOT TARGET Catch2::Catch2)
    set(CATCH2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
    
    # Catch2 library (headers only, no main)
    add_library(Catch2_local INTERFACE)
    target_include_directories(Catch2_local INTERFACE "${CATCH2_DIR}")
    target_compile_features(Catch2_local INTERFACE cxx_std_17)
    add_library(Catch2::Catch2 ALIAS Catch2_local)
    
    # Catch2WithMain library (includes amalgamated source + main)
    add_library(Catch2WithMain_local STATIC
        "${CATCH2_DIR}/catch2/catch_amalgamated.cpp"
    )
    target_include_directories(Catch2WithMain_local PUBLIC "${CATCH2_DIR}")
    target_compile_features(Catch2WithMain_local PUBLIC cxx_std_17)
    target_link_libraries(Catch2WithMain_local PUBLIC Catch2::Catch2)
    
    # Match the runtime library setting to avoid LNK2038 errors
    if(MSVC)
        set_target_properties(Catch2WithMain_local PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        )
    endif()
    
    add_library(Catch2::Catch2WithMain ALIAS Catch2WithMain_local)
endif()

# Enable CTest support for this sub-project
enable_testing()

# ------------------------------------------------------------------------------
# Crypto++
# ------------------------------------------------------------------------------

set(CRYPTOPP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../external/cryptopp")

set(CRYPTOPP_INCLUDE_DIR
    "${CRYPTOPP_ROOT}/include"
)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    set(CRYPTOPP_LIB
        "${CRYPTOPP_ROOT}/lib/cryptopp.lib"
    )

elseif(MINGW)

    set(CRYPTOPP_LIB
        "${CRYPTOPP_ROOT}/lib/libcryptopp.a"
    )

else()

    find_library(
        CRYPTOPP_LIB
        NAMES cryptopp
        PATHS "${CRYPTOPP_ROOT}/lib"
        NO_DEFAULT_PATH
    )

endif()

if(NOT EXISTS "${CRYPTOPP_INCLUDE_DIR}")
    message(FATAL_ERROR
        "Crypto++ include directory not found:\n"
        "${CRYPTOPP_INCLUDE_DIR}"
    )
endif()

if(NOT EXISTS "${CRYPTOPP_LIB}")
    message(FATAL_ERROR
        "Crypto++ library not found:\n"
        "${CRYPTOPP_LIB}"
    )
endif()

message(STATUS "Crypto++ include: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library: ${CRYPTOPP_LIB}")

# ------------------------------------------------------------------------------
# Executable & Shared Library
# ------------------------------------------------------------------------------

add_executable(aestool
    src/main.cpp
    src/crypto_engine.cpp
    src/utils.cpp
)

target_include_directories(aestool PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(aestool PRIVATE
    ${CRYPTOPP_LIB}
)

# ------------------------------------------------------------------------------
# Shared Library (DLL for Python GUI)
# ------------------------------------------------------------------------------

add_library(aestool_lib SHARED
    src/dll_wrapper.cpp
    src/crypto_engine.cpp
    src/utils.cpp
)

target_include_directories(aestool_lib PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(aestool_lib PRIVATE
    ${CRYPTOPP_LIB}
)

# MinGW: statically link runtime to avoid missing libgcc/libstdc++/libwinpthread DLLs
if(MINGW)
    target_link_options(aestool_lib PRIVATE -static-libgcc -static-libstdc++ -static -lpthread)
endif()

target_compile_definitions(aestool_lib PRIVATE
    BUILDING_DLL
)

# Set output name to aestool (aestool.dll on Windows, libaestool.so on Linux)
set_target_properties(aestool_lib PROPERTIES
    OUTPUT_NAME "aestool"
    PREFIX ""
)

# ------------------------------------------------------------------------------
# Threads
# ------------------------------------------------------------------------------

find_package(Threads REQUIRED)
target_link_libraries(aestool PRIVATE Threads::Threads)
target_link_libraries(aestool_lib PRIVATE Threads::Threads)

# ------------------------------------------------------------------------------
# Unit Tests (Catch2)
# ------------------------------------------------------------------------------

add_executable(catch2_test
    src/tests.cpp
    src/crypto_engine.cpp
    src/utils.cpp
)

target_include_directories(catch2_test PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(catch2_test PRIVATE
    ${CRYPTOPP_LIB}
    Threads::Threads
    Catch2::Catch2  # Headers only - we provide custom main with --help support
)

# Add Catch2 amalgamated source (since we're using Catch2::Catch2 without main)
target_sources(catch2_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include/catch2/catch_amalgamated.cpp
)

# Tell catch_amalgamated.cpp to NOT define main() - we provide our own
target_compile_definitions(catch2_test PRIVATE
    CATCH_AMALGAMATED_CUSTOM_MAIN
)

# Register test with CTest
add_test(NAME aestool_unit_tests COMMAND catch2_test)

# ------------------------------------------------------------------------------
# Benchmark Executable
# ------------------------------------------------------------------------------

add_executable(benchmark
    src/benchmark.cpp
    src/crypto_engine.cpp
    src/utils.cpp
)

target_include_directories(benchmark PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(benchmark PRIVATE
    ${CRYPTOPP_LIB}
    Threads::Threads
)

# ------------------------------------------------------------------------------
# Compiler-specific optimization flags for benchmark
if(MSVC)
    target_compile_options(benchmark PRIVATE
        /O2     # Maximize speed
        /Oi     # Enable intrinsic functions
        /Ot     # Favor fast code
        /GL     # Whole program optimization (link-time)
    )
    target_link_options(benchmark PRIVATE /LTCG)  # Link-time code generation
else()
    target_compile_options(benchmark PRIVATE
        -O3
        -march=native
        -mtune=native
    )
    target_link_options(benchmark PRIVATE -flto)
endif()

# Compiler warnings (MUST be after all target definitions)
# ------------------------------------------------------------------------------

if(MSVC)

    target_compile_options(aestool PRIVATE
        /W4
        /permissive-
    )
    target_compile_options(aestool_lib PRIVATE
        /W4
        /permissive-
    )
    target_compile_options(catch2_test PRIVATE /W4 /permissive-)
    target_compile_options(benchmark PRIVATE /W4 /permissive-)

else()

    target_compile_options(aestool PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
    target_compile_options(aestool_lib PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
    target_compile_options(catch2_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(benchmark PRIVATE -Wall -Wextra -Wpedantic)

endif()

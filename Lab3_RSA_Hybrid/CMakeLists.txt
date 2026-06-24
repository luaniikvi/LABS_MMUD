cmake_minimum_required(VERSION 3.15)

project(Lab3_RSA_Hybrid LANGUAGES CXX)

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
    message(STATUS "[Lab3] Compiling with MSVC")
    set(COMPILER_NAME "msvc")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
elseif(MINGW)
    message(STATUS "[Lab3] Compiling with MinGW (MSYS2)")
    set(COMPILER_NAME "mingw")
    # Statically link MinGW runtime so no libgcc/libstdc++/libwinpthread DLLs needed
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static -lpthread")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static -lpthread")
    
    # Find MinGW bin directory for DLL fallback copy
    get_filename_component(MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    message(STATUS "[Lab3] MinGW bin dir: ${MINGW_BIN_DIR}")
else()
    message(STATUS "[Lab3] Compiling with GCC/Clang")
    set(COMPILER_NAME "gcc")
endif()

# ------------------------------------------------------------------------------
# Catch2 — local amalgamation
# ------------------------------------------------------------------------------
if(NOT TARGET Catch2::Catch2WithMain)
    set(CATCH2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/catch2")
    add_library(Catch2WithMain_lab3 STATIC
        "${CATCH2_DIR}/catch_amalgamated.cpp"
    )
    target_include_directories(Catch2WithMain_lab3 PUBLIC "${CATCH2_DIR}")
    target_compile_features(Catch2WithMain_lab3 PUBLIC cxx_std_17)
    add_library(Catch2::Catch2WithMain ALIAS Catch2WithMain_lab3)
endif()

# ------------------------------------------------------------------------------
# Crypto++
# ------------------------------------------------------------------------------
set(CRYPTOPP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../external/cryptopp")

set(CRYPTOPP_INCLUDE_DIR
    "${CRYPTOPP_ROOT}/include"
)

# Platform-specific library paths
if(MSVC)
    # MSVC: Use .lib files
    set(CRYPTOPP_LIB_RELEASE "${CRYPTOPP_ROOT}/lib/cryptopp.lib")
    set(CRYPTOPP_LIB_DEBUG "${CRYPTOPP_ROOT}/lib/cryptopp.lib")
    
    if(EXISTS "${CRYPTOPP_LIB_RELEASE}")
        set(CRYPTOPP_LIB optimized "${CRYPTOPP_LIB_RELEASE}" debug "${CRYPTOPP_LIB_DEBUG}")
        message(STATUS "[Lab3] Found Crypto++ (MSVC): ${CRYPTOPP_LIB_RELEASE}")
    else()
        message(FATAL_ERROR "[Lab3] Crypto++ library not found at ${CRYPTOPP_LIB_RELEASE}\n"
                            "Please build Crypto++ first for MSVC.")
    endif()
    
elseif(MINGW OR CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    # MinGW/Linux: Use .a static libraries
    set(CRYPTOPP_LIB "${CRYPTOPP_ROOT}/libcryptopp.a")
    
    if(NOT EXISTS "${CRYPTOPP_LIB}")
        # Try alternative paths for MinGW
        set(CRYPTOPP_LIB "${CRYPTOPP_ROOT}/lib/libcryptopp.a")
    endif()
    
    if(EXISTS "${CRYPTOPP_LIB}")
        message(STATUS "[Lab3] Found Crypto++ (MinGW/Linux): ${CRYPTOPP_LIB}")
    else()
        message(FATAL_ERROR "[Lab3] Crypto++ library not found at ${CRYPTOPP_LIB}\n"
                            "Please build Crypto++ first for MinGW/MSYS2.")
    endif()
else()
    # Fallback: try to find library
    find_library(CRYPTOPP_LIB
        NAMES cryptopp libcryptopp
        PATHS "${CRYPTOPP_ROOT}/lib" "${CRYPTOPP_ROOT}"
        NO_DEFAULT_PATH
    )
    
    if(NOT CRYPTOPP_LIB)
        message(FATAL_ERROR "[Lab3] Crypto++ library not found in ${CRYPTOPP_ROOT}\n"
                            "Please build Crypto++ first.")
    endif()
    
    message(STATUS "[Lab3] Found Crypto++: ${CRYPTOPP_LIB}")
endif()

# ------------------------------------------------------------------------------
# rsatool executable
# ------------------------------------------------------------------------------
add_executable(rsatool
    src/main.cpp
    src/rsa_engine.cpp
    src/rsa_engine.hpp
    src/hybrid_engine.cpp
    src/hybrid_engine.hpp
    src/utils.cpp
    src/utils.hpp
    src/benchmark.cpp
)

target_include_directories(rsatool PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(rsatool PRIVATE
    ${CRYPTOPP_LIB}
)

target_compile_definitions(rsatool PRIVATE
    $<$<CONFIG:Debug>:DEBUG_BUILD>
)

# Compiler-specific warning flags
if(MSVC)
    target_compile_options(rsatool PRIVATE /W4 /WX-)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(rsatool PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

# Install target
install(TARGETS rsatool
    RUNTIME DESTINATION bin
)

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------
add_executable(catch2_test
    src/tests.cpp
    src/rsa_engine.cpp
    src/rsa_engine.hpp
    src/hybrid_engine.cpp
    src/hybrid_engine.hpp
    src/utils.cpp
    src/utils.hpp
)

target_include_directories(catch2_test PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(catch2_test PRIVATE
    ${CRYPTOPP_LIB}
    Catch2::Catch2WithMain
)

# Compiler-specific warning flags
if(MSVC)
    target_compile_options(catch2_test PRIVATE /W4 /WX-)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(catch2_test PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

# Register tests with CTest (manual registration for local Catch2)
enable_testing()
add_test(NAME Lab3_Tests COMMAND catch2_test WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

# ------------------------------------------------------------------------------
# Benchmark executable
# ------------------------------------------------------------------------------
add_executable(benchmark
    src/benchmark_main.cpp
    src/rsa_engine.cpp
    src/rsa_engine.hpp
    src/hybrid_engine.cpp
    src/hybrid_engine.hpp
    src/utils.cpp
    src/utils.hpp
    src/benchmark.cpp
)

target_include_directories(benchmark PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(benchmark PRIVATE
    ${CRYPTOPP_LIB}
)

# Compiler-specific warning flags
if(MSVC)
    target_compile_options(benchmark PRIVATE /W4 /WX-)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(benchmark PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
endif()

# Install benchmark
install(TARGETS benchmark
    RUNTIME DESTINATION bin
)

# ------------------------------------------------------------------------------
# DLL Library for Python GUI
# ------------------------------------------------------------------------------

add_library(rsatool_lib SHARED
    src/dll_wrapper.cpp
    src/rsa_engine.cpp
    src/hybrid_engine.cpp
    src/utils.cpp
)

target_include_directories(rsatool_lib PRIVATE
    ${CRYPTOPP_INCLUDE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(rsatool_lib PRIVATE
    ${CRYPTOPP_LIB}
)

target_compile_definitions(rsatool_lib PRIVATE
    BUILDING_DLL
)

if(MSVC)
    target_compile_options(rsatool_lib PRIVATE /W4)
else()
    target_compile_options(rsatool_lib PRIVATE -Wall -Wextra -pedantic)
endif()

# Set output name to rsatool (rsatool.dll on Windows, librsatool.so on Linux)
set_target_properties(rsatool_lib PROPERTIES
    OUTPUT_NAME "rsatool"
    PREFIX ""
)

# ------------------------------------------------------------------------------
# MinGW: Post-build auto-copy runtime DLLs to build directory
# (MSVC uses static runtime — no DLLs needed)
# ------------------------------------------------------------------------------
if(NOT MSVC)
    # Auto-detect MinGW bin directory from compiler path
    get_filename_component(MINGW_RUNTIME_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)

    # Verify DLLs exist; fallback to common MSYS2 path if not found
    if(NOT EXISTS "${MINGW_RUNTIME_DIR}/libstdc++-6.dll")
        if(EXISTS "C:/msys64/mingw64/bin/libstdc++-6.dll")
            set(MINGW_RUNTIME_DIR "C:/msys64/mingw64/bin")
        endif()
    endif()
    message(STATUS "[Lab3] MinGW runtime DLL dir: ${MINGW_RUNTIME_DIR}")

    set(MINGW_RUNTIME_DLLS
        "libgcc_s_seh-1.dll"
        "libstdc++-6.dll"
        "libwinpthread-1.dll"
    )

    foreach(_target rsatool catch2_test benchmark rsatool_lib)
        foreach(_dll ${MINGW_RUNTIME_DLLS})
            add_custom_command(TARGET ${_target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${MINGW_RUNTIME_DIR}/${_dll}"
                    "$<TARGET_FILE_DIR:${_target}>/${_dll}"
            )
        endforeach()
    endforeach()
endif()
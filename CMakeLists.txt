cmake_minimum_required(VERSION 3.15)
project(CryptographyLabs LANGUAGES CXX)

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

# Catch2 is provided as a local amalgamation in Lab1_Symmetric/include/catch2/
# No FetchContent needed — Lab subdirectory sets up the target.

# Enable testing globally
enable_testing()

# Add Labs
add_subdirectory(Lab1_Symmetric)
padd_subdirectory(Lab3_RSA_Hybrid)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Try to locate MinGW in standard MSYS2 paths.
if(NOT DEFINED CMAKE_C_COMPILER)
  find_program(CMAKE_C_COMPILER NAMES x86_64-w64-mingw32-gcc gcc
    PATHS "C:/msys64/mingw64/bin" ENV PATH
  )
endif()
if(NOT DEFINED CMAKE_CXX_COMPILER)
  find_program(CMAKE_CXX_COMPILER NAMES x86_64-w64-mingw32-g++ g++
    PATHS "C:/msys64/mingw64/bin" ENV PATH
  )
endif()
if(NOT DEFINED CMAKE_RC_COMPILER)
  find_program(CMAKE_RC_COMPILER NAMES x86_64-w64-mingw32-windres windres
    PATHS "C:/msys64/mingw64/bin" ENV PATH
  )
endif()
if(NOT DEFINED CMAKE_C_COMPILER OR NOT DEFINED CMAKE_CXX_COMPILER)
  message(FATAL_ERROR "Could not find MinGW compilers in PATH: ${CMAKE_CXX_COMPILER}")
endif()

# Avoid mixed CRTS.
set(CMAKE_C_FLAGS_INIT "${CMAKE_C_FLAGS_INIT} -static-libgcc")
set(CMAKE_CXX_FLAGS_INIT "${CMAKE_CXX_FLAGS_INIT} -static-libgcc -static-libstdc++")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${CMAKE_SHARED_LINKER_FLAGS_INIT} -static-libgcc -static-libstdc++")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${CMAKE_EXE_LINKER_FLAGS_INIT} -static-libgcc -static-libstdc++")

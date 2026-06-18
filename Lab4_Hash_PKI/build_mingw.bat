@echo off
set CMAKE="C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set GPP=C:\msys64\mingw64\bin\g++.exe
set GCC=C:\msys64\mingw64\bin\gcc.exe
set MAKE=C:\msys64\usr\bin\make.exe

rmdir /s /q "E:\MatMaUngDung\Labs\Lab4_Hash_PKI\build_mingw" 2>nul

%CMAKE% -S "E:/MatMaUngDung/Labs/Lab4_Hash_PKI" -B "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/build_mingw" -G "MinGW Makefiles" -DCMAKE_CXX_COMPILER=%GPP% -DCMAKE_C_COMPILER=%GCC% -DCMAKE_MAKE_PROGRAM=%MAKE% > "E:\MatMaUngDung\Labs\Lab4_Hash_PKI\mingw_config.txt" 2>&1
echo CONFIG EXIT: %ERRORLEVEL% >> "E:\MatMaUngDung\Labs\Lab4_Hash_PKI\mingw_config.txt"

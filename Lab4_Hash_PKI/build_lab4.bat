@echo off
set CMAKE="C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

rmdir /s /q "E:\MatMaUngDung\Labs\Lab4_Hash_PKI\build" 2>nul

%CMAKE% -S "E:/MatMaUngDung/Labs/Lab4_Hash_PKI" -B "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/build" -G "Visual Studio 18 2026" > "E:\MatMaUngDung\Labs\Lab4_Hash_PKI\cmake_output.txt" 2>&1
echo CONFIG EXIT: %ERRORLEVEL% >> "E:\MatMaUngDung\Labs\Lab4_Hash_PKI\cmake_output.txt"

%CMAKE% --build "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/build" --config Release > "E:\MatMaUngDung\Labs\Lab4_Hash_PKI\cmake_build_output.txt" 2>&1
echo BUILD EXIT: %ERRORLEVEL% >> "E:\MatMaUngDung\Labs\Lab4_Hash_PKI\cmake_build_output.txt"

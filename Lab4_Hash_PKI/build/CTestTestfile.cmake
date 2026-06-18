# CMake generated Testfile for 
# Source directory: E:/MatMaUngDung/Labs/Lab4_Hash_PKI
# Build directory: E:/MatMaUngDung/Labs/Lab4_Hash_PKI/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(Lab4_Tests "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/build/Debug/catch2_test.exe")
  set_tests_properties(Lab4_Tests PROPERTIES  WORKING_DIRECTORY "E:/MatMaUngDung/Labs/Lab4_Hash_PKI" _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/CMakeLists.txt;198;add_test;E:/MatMaUngDung/Labs/Lab4_Hash_PKI/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(Lab4_Tests "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/build/Release/catch2_test.exe")
  set_tests_properties(Lab4_Tests PROPERTIES  WORKING_DIRECTORY "E:/MatMaUngDung/Labs/Lab4_Hash_PKI" _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/CMakeLists.txt;198;add_test;E:/MatMaUngDung/Labs/Lab4_Hash_PKI/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(Lab4_Tests "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/build/MinSizeRel/catch2_test.exe")
  set_tests_properties(Lab4_Tests PROPERTIES  WORKING_DIRECTORY "E:/MatMaUngDung/Labs/Lab4_Hash_PKI" _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/CMakeLists.txt;198;add_test;E:/MatMaUngDung/Labs/Lab4_Hash_PKI/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(Lab4_Tests "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/build/RelWithDebInfo/catch2_test.exe")
  set_tests_properties(Lab4_Tests PROPERTIES  WORKING_DIRECTORY "E:/MatMaUngDung/Labs/Lab4_Hash_PKI" _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab4_Hash_PKI/CMakeLists.txt;198;add_test;E:/MatMaUngDung/Labs/Lab4_Hash_PKI/CMakeLists.txt;0;")
else()
  add_test(Lab4_Tests NOT_AVAILABLE)
endif()

# CMake generated Testfile for 
# Source directory: E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid
# Build directory: E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(Lab3_Tests "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/build/Debug/catch2_test.exe")
  set_tests_properties(Lab3_Tests PROPERTIES  WORKING_DIRECTORY "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid" _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/CMakeLists.txt;181;add_test;E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(Lab3_Tests "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/build/Release/catch2_test.exe")
  set_tests_properties(Lab3_Tests PROPERTIES  WORKING_DIRECTORY "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid" _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/CMakeLists.txt;181;add_test;E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(Lab3_Tests "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/build/MinSizeRel/catch2_test.exe")
  set_tests_properties(Lab3_Tests PROPERTIES  WORKING_DIRECTORY "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid" _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/CMakeLists.txt;181;add_test;E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(Lab3_Tests "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/build/RelWithDebInfo/catch2_test.exe")
  set_tests_properties(Lab3_Tests PROPERTIES  WORKING_DIRECTORY "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid" _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/CMakeLists.txt;181;add_test;E:/MatMaUngDung/Labs/Lab3_RSA_Hybrid/CMakeLists.txt;0;")
else()
  add_test(Lab3_Tests NOT_AVAILABLE)
endif()

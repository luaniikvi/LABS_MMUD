# CMake generated Testfile for 
# Source directory: E:/MatMaUngDung/Labs/Lab1_Symmetric
# Build directory: E:/MatMaUngDung/Labs/Lab1_Symmetric/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(aestool_unit_tests "E:/MatMaUngDung/Labs/Lab1_Symmetric/build/Debug/aestool_tests.exe")
  set_tests_properties(aestool_unit_tests PROPERTIES  _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab1_Symmetric/CMakeLists.txt;193;add_test;E:/MatMaUngDung/Labs/Lab1_Symmetric/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(aestool_unit_tests "E:/MatMaUngDung/Labs/Lab1_Symmetric/build/Release/aestool_tests.exe")
  set_tests_properties(aestool_unit_tests PROPERTIES  _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab1_Symmetric/CMakeLists.txt;193;add_test;E:/MatMaUngDung/Labs/Lab1_Symmetric/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(aestool_unit_tests "E:/MatMaUngDung/Labs/Lab1_Symmetric/build/MinSizeRel/aestool_tests.exe")
  set_tests_properties(aestool_unit_tests PROPERTIES  _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab1_Symmetric/CMakeLists.txt;193;add_test;E:/MatMaUngDung/Labs/Lab1_Symmetric/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(aestool_unit_tests "E:/MatMaUngDung/Labs/Lab1_Symmetric/build/RelWithDebInfo/aestool_tests.exe")
  set_tests_properties(aestool_unit_tests PROPERTIES  _BACKTRACE_TRIPLES "E:/MatMaUngDung/Labs/Lab1_Symmetric/CMakeLists.txt;193;add_test;E:/MatMaUngDung/Labs/Lab1_Symmetric/CMakeLists.txt;0;")
else()
  add_test(aestool_unit_tests NOT_AVAILABLE)
endif()

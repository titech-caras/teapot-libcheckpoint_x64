project(libcheckpoint_x64)
cmake_minimum_required(VERSION 3.18)

set(CMAKE_C_COMPILER clang)

set(CMAKE_C_FLAGS_DEBUG "-g ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O3 ${CMAKE_C_FLAGS}")

find_package(ZLIB)

add_library(checkpoint_x64 checkpoint.c checkpoint_asm.c signal_handler.c dift_support.c dift_wrappers.c report_gadget.c)
set_source_files_properties(checkpoint_asm.c PROPERTIES COMPILE_FLAGS -O0)
install(TARGETS checkpoint_x64 ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

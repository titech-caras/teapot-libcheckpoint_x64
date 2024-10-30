project(libcheckpoint_x64)
cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_COMPILER clang)

set(CMAKE_C_FLAGS_DEBUG "-g ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O3 ${CMAKE_C_FLAGS}")

find_package(ZLIB)

set(SOURCE_LIST checkpoint.c checkpoint_asm.c signal_handler.c dift_support.c dift_wrappers.c report_gadget.c)
set_source_files_properties(checkpoint_asm.c PROPERTIES COMPILE_FLAGS -O0)

add_library(checkpoint_x64 ${SOURCE_LIST})
install(TARGETS checkpoint_x64 ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

add_library(checkpoint_x64_nonest ${SOURCE_LIST})
target_compile_options(checkpoint_x64_nonest PRIVATE -DNO_NESTED_SPECULATION)
install(TARGETS checkpoint_x64_nonest ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

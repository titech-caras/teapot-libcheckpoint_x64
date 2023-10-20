project(libcheckpoint_x64)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")

add_library(checkpoint_x64 checkpoint.c checkpoint_asm.c signal_handler.c
        dift_support.c
        dift_support.h)
set_source_files_properties(checkpoint_asm.c PROPERTIES COMPILE_FLAGS -O0)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_C_FLAGS "-O3")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

# Set the include paths
#set(CMAKE_C_FLAGS "-O0 -g3 -ggdb3  -Wl,-z,norelro")
#set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")
#set(CMAKE_EXE_LINKER_FLAGS "-static -z norelro")
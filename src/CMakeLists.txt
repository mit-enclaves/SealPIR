find_package(SEAL 4.1.1 REQUIRED)

get_filename_component(CUR_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,${CUR_DIR}/eh_frame_symbols.ld")

add_library(sealpir pir.hpp pir.cpp pir_client.hpp pir_client.cpp pir_server.hpp
  pir_server.cpp)
target_link_libraries(sealpir PUBLIC SEAL::seal c++ c++abi m pthread dl util rt c)

add_executable(main main.cpp)
target_link_libraries(main PRIVATE sealpir
  c++ -Wl,--whole-archive c++abi -Wl,--no-whole-archive m pthread dl util rt c
)
find_package(SEAL 4.1.2 REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(sealpir pir.hpp pir.cpp pir_client.hpp pir_client.cpp pir_server.hpp
  pir_server.cpp SHA256.cpp)
target_link_libraries(sealpir SEAL::seal)

add_executable(main main.cpp)
target_link_libraries(main sealpir)

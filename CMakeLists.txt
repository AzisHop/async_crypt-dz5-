cmake_minimum_required(VERSION 3.19)
project(async_crypt_dz5_)

set(CMAKE_CXX_STANDARD 17)

add_executable(async_crypt_dz5_ main.cpp)

target_link_libraries(async_crypt_dz5_ -lcryptopp)
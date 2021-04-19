cmake_minimum_required(VERSION 3.19)
project(async_crypt_dz5_)

include_directories(./include)

set(CMAKE_CXX_STANDARD 17)

add_executable(async_crypt_dz5_ main.cpp src/Car.cpp include/Car.h src/Trinket.cpp include/Trinket.h src/Utils.cpp include/Utils.h)

target_link_libraries(async_crypt_dz5_ -lcryptopp)
cmake_minimum_required(VERSION 3.2)
project(Socks5Server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -O3 -pthread")

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})

set(SOCKS5_INSTALL_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(SOCKS5_INSTALL_BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(SOCKS5_INSTALL_LIB_DIR ${PROJECT_SOURCE_DIR}/lib)

include_directories(${SOCKS5_INSTALL_INCLUDE_DIR})

add_subdirectory(src)
#add_subdirectory(test)



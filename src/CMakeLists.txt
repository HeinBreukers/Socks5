cmake_minimum_required(VERSION 3.2)
project(socks5)

include_directories(${CMAKE_SOURCE_DIR} ./SOCKS5)

set(SOCKS_SRC 
    SOCKS5/SOCKS5.cpp)
set(SOURCE_FILES main.cpp)

add_executable(socks5example ${SOURCE_FILES} ${SOCKS_SRC})


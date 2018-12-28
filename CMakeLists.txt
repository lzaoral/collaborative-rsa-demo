cmake_minimum_required(VERSION 3.1)
project(collabrsa)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra -pedantic -Wold-style-cast")

link_libraries(ssl crypto)

set(HEADERS common.hpp bignum_wrapper.hpp)
set(SOURCES common.cpp)

add_executable(main_client main_client.cpp ${HEADERS} ${SOURCES})
add_executable(main_server main_server.cpp ${HEADERS} ${SOURCES})

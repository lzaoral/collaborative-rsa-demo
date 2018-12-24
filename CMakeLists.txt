cmake_minimum_required(VERSION 3.1)
project(collabrsa)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra -pedantic -Wold-style-cast")
link_libraries(ssl crypto)

set(HEADERS common.hpp bignum_wrapper.hpp)
set(SOURCES common.cpp)

add_executable(main_client main_client.cpp ${HEADERS} ${SOURCES})

# set(COLLAB_RSA_SERVER_SOURCE server/main_server.c server/common_server.c)
# set(COLLAB_RSA_SERVER_HEADERS server/common_server.h)
# add_executable(main_server ${COLLAB_RSA_SERVER_SOURCE} ${COLLAB_RSA_SERVER_HEADERS})

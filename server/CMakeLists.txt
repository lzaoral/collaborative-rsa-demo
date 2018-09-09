cmake_minimum_required(VERSION 3.5)
project(collabrsa)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -Wextra -pedantic")

set(COLLAB_RSA_SERVER_SOURCE main_server.c common_server.c)
set(COLLAB_RSA_SERVER_HEADERS common_server.h)
add_executable(main_server ${COLLAB_RSA_SERVER_SOURCE} ${COLLAB_RSA_SERVER_HEADERS})

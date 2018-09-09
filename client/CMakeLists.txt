cmake_minimum_required(VERSION 3.5)
project(collabrsa)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -Wextra -pedantic")

set(COLLAB_RSA_CLIENT_SOURCE main_client.c common_client.c)
set(COLLAB_RSA_CLIENT_HEADERS common_client.h)
add_executable(main_client ${COLLAB_RSA_CLIENT_SOURCE} ${COLLAB_RSA_CLIENT_HEADERS})
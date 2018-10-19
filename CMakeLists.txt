cmake_minimum_required(VERSION 3.5)
project(collabrsa)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -Wextra -pedantic")
link_libraries(ssl crypto)

set(COLLAB_RSA_CLIENT_SOURCE client/main_client.c client/common_client.c)
set(COLLAB_RSA_CLIENT_HEADERS client/common_client.h)
add_executable(main_client ${COLLAB_RSA_CLIENT_SOURCE} ${COLLAB_RSA_CLIENT_HEADERS})

set(COLLAB_RSA_SERVER_SOURCE server/main_server.c server/common_server.c)
set(COLLAB_RSA_SERVER_HEADERS server/common_server.h)
# add_executable(main_server ${COLLAB_RSA_SERVER_SOURCE} ${COLLAB_RSA_SERVER_HEADERS})

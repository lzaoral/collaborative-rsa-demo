cmake_minimum_required(VERSION 3.1)
project(collabrsa)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra -pedantic -Wold-style-cast -v")


find_package(OpenSSL)

if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found")
endif()

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(EXTRA_LIBS ${OPENSSL_LIBRARIES})


set(HEADERS common.hpp bignum_wrapper.hpp rsa_wrapper.hpp)
set(SOURCES common.cpp)

add_executable(main_client main_client.cpp ${HEADERS} ${SOURCES})
target_link_libraries(main_client ${EXTRA_LIBS})

add_executable(main_client_outside main_client_outside.cpp ${HEADERS} ${SOURCES})
target_link_libraries(main_client_outside ${EXTRA_LIBS})

add_executable(main_server main_server.cpp ${HEADERS} ${SOURCES})
target_link_libraries(main_server ${EXTRA_LIBS})

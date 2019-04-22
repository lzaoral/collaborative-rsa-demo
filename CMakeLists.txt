cmake_minimum_required(VERSION 3.1)
project(smpc_rsa)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wextra -pedantic -Wold-style-cast")

find_package(OpenSSL)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found")
endif()

add_library(common STATIC common.cpp)
add_library(bignum STATIC bignum_wrapper.cpp)
set(EXTRA_LIBS OpenSSL::Crypto bignum common)

add_executable(smpc_rsa main.cpp)
target_link_libraries(smpc_rsa ${EXTRA_LIBS})

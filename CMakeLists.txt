cmake_minimum_required(VERSION 3.7)
project(smpc_rsa)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -pedantic")

find_package(OpenSSL "1.1.1" REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_program(CLANG_TIDY_BINARY clang-tidy)
if(CLANG_TIDY_BINARY)
  set(CMAKE_CXX_CLANG_TIDY clang-tidy --config=)
  message(STATUS "Using clang-tidy: ${CLANG_TIDY_BINARY}")
else()
  set(CMAKE_CXX_CLANG_TIDY "" FORCE)
endif()

add_library(common STATIC common.cpp
                          common.hpp
                          client_common.hpp
                          server_common.hpp)

add_library(OpenSSLwrapper STATIC bignum_wrapper.cpp
                                  bignum_wrapper.hpp
                                  rsa_wrapper.hpp)
target_link_libraries(OpenSSLwrapper OpenSSL::Crypto)

add_executable(smpc_rsa main.cpp)
target_link_libraries(smpc_rsa OpenSSLwrapper common)

cmake_minimum_required(VERSION 3.7)
project(smpc_rsa)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -pedantic")

include(FindOpenSSL)
find_package(OpenSSL "1.1.1" REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(CMAKE_CXX_CLANG_TIDY clang-tidy --config=)

add_library(common STATIC common.cpp
                          common.hpp
                          client_common.hpp
                          server_common.hpp)

add_library(OpenSSLwrapper STATIC bignum_wrapper.cpp
                                  bignum_wrapper.hpp
                                  rsa_wrapper.hpp)

add_executable(smpc_rsa main.cpp)
target_link_libraries(smpc_rsa OpenSSL::Crypto OpenSSLwrapper common)

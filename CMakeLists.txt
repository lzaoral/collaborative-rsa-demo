cmake_minimum_required(VERSION 3.1)
project(smpc_rsa)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wextra -pedantic -Wold-style-cast")

find_package(OpenSSL REQUIRED)

if (NOT "${OPENSSL_VERSION}" MATCHES "1.1.1*")
    message(FATAL_ERROR "OpenSSL 1.1.1 not found")
endif ()

add_library(common STATIC common.cpp common.hpp client_common.hpp server_common.hpp)
add_library(openSSLwrapper STATIC bignum_wrapper.cpp bignum_wrapper.hpp rsa_wrapper.hpp)
set(EXTRA_LIBS OpenSSL::Crypto openSSLwrapper common)

add_executable(smpc_rsa main.cpp)
target_link_libraries(smpc_rsa ${EXTRA_LIBS})

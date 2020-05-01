# JavaCard SMPC RSA Reference Implementation

[![Build Status](https://travis-ci.org/lzaoral/collaborative-rsa-demo.svg?branch=master)](https://travis-ci.org/lzaoral/collaborative-rsa-demo)

Reference implementation of the adaptation of the Smart-ID scheme for smart
cards.

## Required

* Compiler supporting C++14 or newer required
* CMake 3.7.0 or newer required
* OpenSSL library 1.1.1a or newer required

## Compilation

```shell
cmake -S . -B build && cd build && make
```

## Usage

```shell
./smpc_rsa [mode] [action]
```

## Stress Testing

The `smpc_test.sh` can be used to test the reference implementation and to
determine the success rate of usable moduli generation of the reference
implementation. Expects the `smpc_rsa` and `message.txt` files in the `build`
directory.

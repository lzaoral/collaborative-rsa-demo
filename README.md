# JavaCard SMPC RSA Reference Implementation

## Required

* Compiler supporting C++14 or newer required
* CMake 3.0.4 or newer required
* OpenSSL library 1.1.1 or newer required

## Compilation

```
cmake -S . -Bbuild && cd build && make
```

## Usage

```
./smpc_rsa [mode] [action]
```

## Stress Testing

The `smpc_test.sh` can be used to test the reference implementation and to
determine the success rate of usable moduli generation of the reference
implementation. Expects the `smpc_rsa` and `message.txt` files in the `build`
folder.


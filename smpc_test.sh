#! /bin/bash

cd build

for i in {1..1000}; do
    printf "TEST ${i}: "
    
    if ! yes | ./smpc_rsa client generate > /dev/null; then
        continue
    fi

    if ! ./smpc_rsa client sign > /dev/null; then
        continue
    fi

    if ! yes | ./smpc_rsa server generate > /dev/null; then
        continue
    fi

    if ! ./smpc_rsa server sign > /dev/null; then
        continue
    fi

    if ! ./smpc_rsa server verify > /dev/null; then
        continue
    fi

    printf "\x1b[1;32mOK\x1b[0m\n"
done;

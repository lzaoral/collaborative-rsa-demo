#! /bin/bash

MAX_ROUNDS=1000
FAIL_GEN_COUNT=0

cd build

if [ ! -f "./smpc_rsa" ]; then
    echo "Reference implementation is missing. Please, build it, see README.md for more information."
    exit 1
fi

if [ ! -f "message.txt" ]; then
    echo "Message file is missing in the 'build' directory. Creating one..."
    echo "a454564654d654654e654654f654654" > message.txt
fi

for i in $(seq $MAX_ROUNDS); do
    printf "TEST $i: "
   
    if ! (yes | ./smpc_rsa client generate) > /dev/null; then
        exit 1
    fi

    if ! (yes | ./smpc_rsa server generate) > /dev/null; then
	((FAIL_GEN_COUNT++))
        continue
    fi
    
    if ! ./smpc_rsa client sign > /dev/null; then
	exit 1
    fi

    if ! ./smpc_rsa server sign > /dev/null; then
	exit 1
    fi

    if ! ./smpc_rsa server verify > /dev/null; then
        exit 1
    fi

    printf "\x1b[1;32mOK\x1b[0m\n"
done;

printf "Result: %d/%d, %d%% failed\n" $FAIL_GEN_COUNT $MAX_ROUNDS $(($FAIL_GEN_COUNT * 100 / $MAX_ROUNDS))

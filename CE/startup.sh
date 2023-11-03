#!/bin/bash

function build()
{
    cd customer_enclave/keys_generation
    rm generate_key_pair.so
    gcc -shared -o generate_key_pair.so generate_key_pair.c -lssl -lcrypto
    cd ../..

    make clean
    make SGX=1
}

function start()
{
    gramine-sgx python customer_enclave/ce.py
}

function clean()
{
    make clean
    rm customer_enclave/keys_generation/generate_key_pair.so
}

function echo_help()
{
    echo "Usage: ce.sh [start|build|clean|help]"
}

if [[ $# != 1 ]]; then
        echo_help
        exit
fi

case $1 in
    build) build
            ;;
    start) start
            ;;
    clean) clean
            ;;
    help)  echo_help
            ;;
    *)    echo_help
            ;;
esac

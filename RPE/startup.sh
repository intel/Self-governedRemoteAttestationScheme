#!/bin/bash

function build()
{
    cd relying_party_enclave/quote_verification
    rm -rf build/ 
    swig -c++ -python verify_dcap_quote.i
    python3 setup.py build
    cp build/lib.*/*.so .
    cd ../..
    
    cd relying_party_enclave/keys_generation
    rm generate_key_pair.so
    gcc -shared -o generate_key_pair.so generate_key_pair.c -lssl -lcrypto
    cd ../..
    
    make clean
    make SGX=1
}

function start()
{
    gramine-sgx python relying_party_enclave/rpe.py
}

function clean()
{
    make clean
    rm -rf relying_party_enclave/quote_verification/build/
    rm relying_party_enclave/quote_verification/*.so
    rm relying_party_enclave/quote_verification/*.cxx
    rm relying_party_enclave/keys_generation/generate_key_pair.so
}

function echo_help()
{
    echo "Usage: rpe.sh [start|build|clean|help]"
}

if [ $# != 1 ]; then
        echo_help
        exit
fi

case $1 in
    build) build
            ;;
    start) start
            ;;
    help)  echo_help
            ;;
    clean) clean
            ;;
    *)    echo_help
            ;;
esac

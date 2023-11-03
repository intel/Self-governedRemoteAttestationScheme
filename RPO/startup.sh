#!/bin/bash

function build()
{
    python3 -m venv venv
    source venv/bin/activate
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
    deactivate
    make clean
    make RATLS
}

function build_sgx()
{
    make clean
    make SGX=1
}

function start()
{   
    source venv/bin/activate
    export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE="1" && \
    export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE="1" && \
    python3 relying_party_owner/rpo.py
    deactivate
}

function start_sgx()
{
    gramine-sgx python relying_party_owner/rpo.py
}

function clean()
{
    make clean
    rm -rf venv
}

function echo_help()
{
    echo "Usage: startup.sh [start|start_sgx|build|build_sgx|help]"
}

if [[ $# != 1 ]]; then
        echo_help
        exit
fi

case $1 in
    build) build
            ;;
    build_sgx) build_sgx
            ;;
    start) start
            ;;
    start_sgx) start_sgx
            ;;
    clean) clean
            ;;
    help)  echo_help
            ;;
    *)    echo_help
            ;;
esac

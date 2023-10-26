#!/bin/bash

function build()
{
    python3 -m venv venv
    source venv/bin/activate
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
    deactivate
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

function clean()
{
    make clean
    rm -rf venv
}

function sgx()
{
    gramine-sgx python relying_party_owner/rpo.py
}

function echo_help()
{
    echo "Usage: startup.sh [start|build|help]"
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
    sgx) sgx
	    ;;
    help)  echo_help
            ;;
    *)    echo_help
            ;;
esac

#!/bin/bash

function build()
{
    python3 -m venv venv
    source venv/bin/activate
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt
    deactivate
}

function start()
{   
    export TCF_HOME=fabric_client
    source venv/bin/activate
    python3 fabric_client/conductor.py
    deactivate
}

function clean()
{
    rm -rf venv
}

function echo_help()
{
    echo "Usage: startup.sh [start|build|clean|help]"
}

if [ $# != 1 ]; then
        echo_help
        exit
fi

case $1 in
    start) start
            ;;
    help)  echo_help
            ;;
    build) build
            ;;
    clean) clean
            ;;
    *)    echo_help
            ;;
esac

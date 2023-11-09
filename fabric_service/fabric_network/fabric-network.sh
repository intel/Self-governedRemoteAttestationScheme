#!/bin/bash

HLF_VERSION=1.4.12
FAVRIC_CA_VERSION=1.4.9

function build_fabric()
{
if [ ! -d venv ]; then
  docker pull hyperledger/fabric-peer:1.4.12
  docker pull hyperledger/fabric-orderer:1.4.12
  docker pull hyperledger/fabric-ccenv:1.4.6
  docker pull hyperledger/fabric-baseos:amd64-0.4.22
  python3 -m venv venv
  source venv/bin/activate
  python3 -m pip install --upgrade pip
  python3 -m pip install -r requirements.txt
  deactivate
else
  echo "Fabric already build. Nothing need to do."
fi
}

function start_network()
{
HLF_VERSION=${HLF_VERSION} docker-compose -f fixtures/docker-compose-2orgs-4peers-tls.yaml up -d
source venv/bin/activate
export PATH=$(pwd)/bin:$PATH
python3 deploy_fabric.py
deactivate
echo "Running containers:"
docker ps --format '{{.Names}}'
}

function stop_network()
{
HLF_VERSION=${HLF_VERSION} docker-compose -f fixtures/docker-compose-2orgs-4peers-tls.yaml down
}

function restart_network()
{
stop_network
start_network
}

function echo_help()
{
    echo "$0 [build|start|restart|clean|stop|help]"
}

function clean_network()
{
    docker rm $(docker ps -aq)
    docker rmi $(docker images -q 'dev-peer*:*latest')
    rm -rf venv/
}

if [[ $# != 1 ]]; then
        echo_help
        exit
fi

case $1 in
    build) build_fabric
	    ;;
    start) start_network
            ;;
    stop)  stop_network
            ;;
    restart) restart_network
            ;;
    clean) clean_network
            ;;
    help)  echo_help
            ;;
    *)     echo_help
            ;;
esac


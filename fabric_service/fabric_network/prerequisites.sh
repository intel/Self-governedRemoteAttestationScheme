#!/bin/bash

# Define those global variables
if [ -f ./variables.sh ]; then
 source ./variables.sh
elif [ -f ./scripts/variables.sh ]; then
 source ./scripts/variables.sh
else
    echo "Cannot find the variables.sh files, pls check"
    exit 1
fi

# Download binaries
./download.sh ${HLF_VERSION} -d -s
rm -rf config/

# Generate crypto-config for relying parties
bin/cryptogen generate \
    --config fixtures/network/crypto-config.yaml \
    --output fixtures/network/crypto-config

# Generate genesis block file
if [ ! -d fixtures/network/${CHANNEL_ARTIFACTS} ]; then
    mkdir fixtures/network/${CHANNEL_ARTIFACTS}
fi

echo "Generate genesis block for system channel using configtx.yaml"

bin/configtxgen \
    -configPath fixtures/network \
    -channelID ${SYS_CHANNEL} \
    -profile ${ORDERER_GENSIS_PROFILE} \
    -outputBlock fixtures/network/${CHANNEL_ARTIFACTS}/${ORDERER_GENSIS}
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

# Rename private key's name
mv fixtures/network/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/keystore/*_sk fixtures/network/crypto-config/ordererOrganizations/example.com/users/Admin@example.com/msp/keystore/priv_sk
mv fixtures/network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/*_sk fixtures/network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/priv_sk
mv fixtures/network/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/*_sk fixtures/network/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk
mv fixtures/network/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/keystore/*_sk fixtures/network/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp/keystore/priv_sk
mv fixtures/network/crypto-config/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/keystore/*_sk fixtures/network/crypto-config/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp/keystore/priv_sk

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

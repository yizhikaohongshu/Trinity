#!/usr/bin/env bash

set -eux

apt install update
apt install upgrade -y
apt install cmake ninja-build libpcap-dev unzip -y

BASE_NAME=$(basename $(pwd))

readonly BASE_NAME

if [ $BASE_NAME != "Trinity" ] && [ $BASE_NAME != "trinity" ]; then
    echo "This script should be executed in the root dir of Trinity."
    exit -1
fi

# Install morden json parser for C++
if [ ! -f "json.hpp" ]; then
    wget https://github.com/nlohmann/json/releases/download/v3.10.5/json.hpp
fi

# Install GFlags
apt install libgflags-dev -y

cd env
chmod +x install_pcap.sh
./install_pcap
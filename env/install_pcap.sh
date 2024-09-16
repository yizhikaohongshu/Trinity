#!/usr/bin/env bash

set -eux

DOWNLOAD_URL="https://github.com/seladb/PcapPlusPlus/releases/download/v23.09/pcapplusplus-23.09-ubuntu-20.04-gcc-9.4.0-x86_64.tar.gz"
DOWNLOAD_FILENAME=${DOWNLOAD_URL##*/}
UNTAR_DIR_NAME=${DOWNLOAD_FILENAME%*.tar.gz}
DIR_NAME="pcapplusplus"

readonly DOWNLOAD_URL DOWNLOAD_FILENAME UNTAR_DIR_NAME DIR_NAME

echo "Installing Libpcap++."

BASE_NAME=$(basename $(pwd))

if [ $BASE_NAME != "env" ]; then
    echo "This script should be executed in the root dir of Trinity."
    exit -1
fi

# if [ -f ${DOWNLOAD_FILENAME} ]; then
#     rm ${DOWNLOAD_FILENAME}
# fi
# if [ -d ${UNTAR_DIR_NAME} ]; then
#     rm -r ${UNTAR_DIR_NAME}
# fi
# if [ -d ${DIR_NAME} ]; then
#     rm -r ${DIR_NAME}
# fi

wget ${DOWNLOAD_URL}
tar -zxf ${DOWNLOAD_FILENAME}
mv ${UNTAR_DIR_NAME} ${DIR_NAME}
cd $_

# back to env
cd ../

rm ${DOWNLOAD_FILENAME}

echo "Done Libpcap++."
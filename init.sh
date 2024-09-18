#!/usr/bin/env bash

set -eux

BASE_NAME=$(basename $(pwd))

if [ $BASE_NAME != "Trinity" ] && [ $BASE_NAME != "trinity" ]; then
    echo "This script should be executed in the root dir of Trinity"
    exit -1
fi

chmod +x ./script/rebuild.sh
./script/rebuild.sh

echo "Done."
#!/bin/bash

# Arguments Check
if [ $# -ne 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [PORT]"
        exit 1
fi

# Configuring Running Directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2

./reg_basic_mt ${server_ip} ${port} 4 50 1024 2>&1 | tee /tmp/reg_basic_mt.txt

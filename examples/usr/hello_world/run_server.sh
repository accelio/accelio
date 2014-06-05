#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/

# Arguments Check
if [ $# -ne 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port]"
        exit 1
fi

server_ip=$1
port=$2

taskset -c 1 ./xio_server ${server_ip} ${port}


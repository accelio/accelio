#!/bin/bash

# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port] [Transport (optional)]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2
trans="rdma"
if [ $# -eq 3 ]; then
	trans=$3
fi

taskset -c 1 ./raio_server ${server_ip} ${port} ${trans}



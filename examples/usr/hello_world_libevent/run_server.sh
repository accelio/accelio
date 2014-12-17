#!/bin/bash

# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port] [Transport (optional)] [0 for infinite run and 1 for finite. Optional, default is 0]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

# Configuring Running Directory
TOP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

server_ip=$1
port=$2
trans="rdma"
if [ $# -eq 3 ]; then
	trans=$3
fi

finite_run=0 #running indefinitely
if [ ! -z "$4" ]
then
	finite_run=$4
fi


taskset -c 1 $TOP_DIR/xio_server ${server_ip} ${port} ${trans} ${finite_run}


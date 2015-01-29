#!/bin/bash

# Get Running Directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR


# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
	echo "Usage: $0 Server-IP Port"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2

./xio_rdma_server -p ${port} ${server_ip}

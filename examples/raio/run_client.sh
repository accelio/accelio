#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/:../../../examples/usr/raio

# Configuring Running Directory
RUNNING_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"


# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port] [Transport (optional)]"
        exit 1
fi

server_ip=$1
port=$2
file=/dev/null
#file=/dev/ram0
block_size=1024
loops=10
trans="rdma"

if [ $# -eq 3 ]; then
	trans=$3
fi


# ./raio_client -a <server_addr> -p <port> -f <file_path>  -b <block_size> -l <loops>
#
taskset -c 1 ${RUNNING_DIR}/raio_client -a ${server_ip} -p ${port} -f ${file} -b ${block_size} -l ${loops} -t ${trans}



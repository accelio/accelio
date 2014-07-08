#!/bin/bash

# Arguments Check
if [ $# -ne 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/:../../../examples/usr/raio

server_ip=$1
port=$2
file=/dev/null
#file=/dev/ram0
block_size=1024
loops=10

# ./raio_client -a <server_addr> -p <port> -f <file_path>  -b <block_size> -l <loops>
#
taskset -c 1 ./raio_client -a ${server_ip} -p ${port} -f ${file} -b ${block_size} -l ${loops}



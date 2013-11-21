#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/:../../../examples/usr/raio

server_ip=192.168.21.126
port=1234
file=/dev/null
#file=/dev/ram0
block_size=1024
loops=10

# ./raio_client -a <server_addr> -p <port> -f <file_path>  -b <block_size> -l <loops>
#
taskset -c 1 ./raio_client -a ${server_ip} -p ${port} -f ${file} -b ${block_size} -l ${loops}



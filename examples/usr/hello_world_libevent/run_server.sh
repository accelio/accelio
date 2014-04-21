#!/bin/bash



export LD_LIBRARY_PATH=../../../src/usr/

server_ip=192.168.1.66
port=1234

taskset -c 1 ./xio_server ${server_ip} ${port}


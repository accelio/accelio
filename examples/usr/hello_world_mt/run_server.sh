#!/bin/bash



export LD_LIBRARY_PATH=../../../src/usr/

#server_ip=[fe80::202:c903:38:d291]
server_ip=192.168.20.126
port=1234

taskset -c 0 ./xio_mt_server ${server_ip} ${port}

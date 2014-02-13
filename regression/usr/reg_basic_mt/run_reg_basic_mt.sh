#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/

#server_ip=[fe80::202:c903:38:d291]
server_ip=192.168.21.127
port=1234

./reg_basic_mt ${server_ip} ${port} 4 50 1024 2>&1 | tee /tmp/reg_basic_mt.txt

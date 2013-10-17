#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=192.168.20.230
port=1234

modprobe xio_client.ko ip=${server_ip} port=${port}

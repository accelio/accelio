#!/bin/bash

server_ip=192.168.20.236
port=1234

modprobe xio_server.ko ip=${server_ip} port=${port}

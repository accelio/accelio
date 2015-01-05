#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/

# Arguments Check
if [ $# -lt 1 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Transport (optional)]"
        exit 1
fi

server_ip=$1
trans="rdma"
intf_name="ib2"
if [ $# -eq 2 ]; then
	trans=$2
fi
start_thread=1

./xio_read_lat -c 8 -n 8 -t 100 -s ${start_thread} -i ${intf_name} -r ${trans} ${server_ip} -o ./xio_read_lat.csv


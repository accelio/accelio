#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/

# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Local Interface] [Transport (optional)]"
        exit 1
fi

server_ip=$1
trans="rdma"
intf=$2

if [ $# -eq 3 ]; then
	trans=$3
fi

./xio_read_bw -c 8 -n 8 -i${intf} -r ${trans} ${server_ip} -o ./xio_read_bw.csv


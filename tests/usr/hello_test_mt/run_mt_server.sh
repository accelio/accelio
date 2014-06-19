#!/bin/bash

# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server-IP] [Port] [data_len. default=0]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2

if [ -z "$3" ]
then
	data_len="0"
else
	data_len=$3
fi

./xio_mt_server -c 6 -p ${port} -n 0 -w ${data_len} ${server_ip} -t 0



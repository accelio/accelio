#!/bin/bash

# Arguments Check
if [ $# -ne 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2

./xio_oneway_server -c 7 -p ${port} -n 0 -w 1024 ${server_ip}
#./xio_oneway_server -c 1 -p ${port} -n 768 -w 512 ${server_ip}
#./xio_oneway_server -c 1 -p ${port} -n 0 -w 16384 ${server_ip}
#./xio_oneway_server -c 1 -p ${port} -n 0 -w 32768 ${server_ip}
#./xio_oneway_server -c 1 -p ${port} -n 0 -w 65536 ${server_ip}
#./xio_oneway_server -c 1 -p ${port} -n 0 -w 131072 ${server_ip}
#./xio_oneway_server -c 1 -p ${port} -n 0 -w 262144 ${server_ip}
#./xio_oneway_server -c 1 -p ${port} -n 0 -w 1048576 ${server_ip}


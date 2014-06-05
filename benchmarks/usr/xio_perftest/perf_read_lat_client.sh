#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/

# Arguments Check
if [ $# -ne 1 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP]"
        exit 1
fi

server_ip=$1

./xio_read_lat -c 8 -n 8 -t 100 ${server_ip}


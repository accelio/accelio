#!/bin/bash

# Arguments Check
if [ $# -ne 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port]"
        exit 1
fi

server_ip=$1
port=$2
transport="rdma"
hdr_len=0
data_len=0
finite_run=0
cpu=0
#cpu=0xaaaa

modprobe xio_server_lat ip=${server_ip} port=${port} transport=${transport} header_len=${hdr_len} data_len=${data_len} finite_run=${finite_run} cpu=${cpu}

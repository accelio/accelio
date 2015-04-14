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
cpu=0
iov_len=1
#cpu=0xaaaa

modprobe xio_hello_server ip=${server_ip} port=${port} transport=${transport} header_len=${hdr_len} data_len=${data_len} iov_len=${iov_len} cpu=${cpu}

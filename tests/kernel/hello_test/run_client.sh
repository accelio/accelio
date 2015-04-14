#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/

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
data_len=1024
finite_run=0
in_iov_len=0
out_iov_len=1
cpu=0
#cpu=0x00aa

modprobe xio_hello_client ip=${server_ip} port=${port} transport=${transport} header_len=${hdr_len} data_len=${data_len} out_iov_len=${out_iov_len} in_iov_len=${in_iov_len} finite_run=${finite_run} cpu=${cpu}

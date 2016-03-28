#!/bin/bash

export LD_LIBRARY_PATH=../../../src/usr/

# Configuring Running Directory
TOP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port] [Transport (optional)] [0 for infinite run and 1 for finite. Optional, default is 0] [Msg size in bytes. Optional, default uses small msgs]"
	echo "Note: small msgs in this context are msg smaller that 8K (configurable) for them rdma_post_send/rdma_post_recv are called instead of rdma_write/rdma_read."
        exit 1
fi

server_ip=$1
port=$2
trans="rdma"
if [ ! -z "$3" ]; then
	trans=$3
fi

finite_run=0 #running indefinitely
if [ ! -z "$4" ]
then
	finite_run=$4
fi

msg_size=0
if [ ! -z "$5" ]
then
	msg_size=$5
fi

taskset -c 1 $TOP_DIR/xio_server ${server_ip} ${port} ${trans} ${finite_run} ${msg_size}


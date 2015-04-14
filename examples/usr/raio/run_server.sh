#!/bin/bash

# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 [Server IP] [Port] [CPU Mask] [Transport (optional)] [0 for infinite run and 1 for finite. default is 0]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

# Configuring Running Directory
RUNNING_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

server_ip=$1
port=$2

if [ -z "$3" ]
then
	cpumask="0xffff"
else
	cpumask=$3
fi

if [ -z "$4" ]
then
	trans="rdma"
else
	trans=$4
fi


if [ -z "$5" ]
then
	#running indefinitely
	finite_run="0"
else
	finite_run=$5
fi


taskset -c 1 ${RUNNING_DIR}/raio_server -a ${server_ip} -p ${port} -c ${cpumask} -t ${trans} -f ${finite_run}




#!/bin/bash

# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 Server IP PORT [max_iterations]"
        exit 1
fi

# Configuring Running Directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2
if [ -z "$3" ]
then
	#running indefenitely
	iterations="0"
else
	iterations=$3
fi


./reg_basic_mt ${server_ip} ${port} ${iterations} 4 50 1024 2>&1 | tee /tmp/reg_basic_mt.txt

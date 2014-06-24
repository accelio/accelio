#!/bin/bash

# Get Running Directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR


# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 Server-IP Port [data_len. default=1024]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2
core=1
ovec=0
hdrlen=0

if [ -z "$3" ]
then
	data_len="1024"
else
	data_len=$3
fi

./xio_server -c ${core} -p ${port} -n ${hdrlen} -w ${data_len}	-l ${ovec} ${server_ip}



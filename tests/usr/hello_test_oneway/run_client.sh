#!/bin/bash

# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
	echo "Usage: $0 Server IP Port [0 for infinite run and 1 for finite. default is 0]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2
if [ -z "$3" ]
then
	#running indefenitely
	finite_run="0"
else
	finite_run=$3
fi

#./xio_oneway_client -c 1 -p ${port} -n 0 -w 0 ${server_ip} -f ${finite_run}
./xio_oneway_client -c 1 -p ${port} -n 0 -w 1024 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 4096 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 8000 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 16384 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 32768 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 65536 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 131072 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 262144 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 524288 ${server_ip} -f ${finite_run}
#./xio_oneway_client -c 1 -p ${port} -n 0 -w 1048576 ${server_ip} -f ${finite_run}



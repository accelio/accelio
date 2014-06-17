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
	#running indefinitely
	finite_run="0"
else
	finite_run=$3
fi

core=1
ivec=0
ovec=1
hdrlen=0


#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 0		-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 1024		-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 4096	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 8192	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 16384	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 32768	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 65536	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 131072	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 262144	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 524288	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}
#./xio_client -c ${core} -p ${port} -n ${hdrlen} -w 1048576	-l ${ovec} -g ${ivec} ${server_ip} -f ${finite_run}



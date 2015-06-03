#!/bin/bash
# Get Running Directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR


# Arguments Check
if [ $# -lt 2 ]; then
        echo "[$0] Missing Parameters!"
        echo "Usage: $0 Server-IP Port [data_len. default=1024] [transport. default=rdma]"
        exit 1
fi

export LD_LIBRARY_PATH=../../../src/usr/

server_ip=$1
port=$2
core=1
ovec=1
hdrlen=0

if [ -z "$3" ]
then
	data_len="1024"
else
	data_len=$3
fi

if [ -z "$4" ]
then
	trans="rdma"
else
	trans=$4
fi

./xio_server -c ${core} -p ${port} -r ${trans} -n ${hdrlen} -w ${data_len}	-l ${ovec} ${server_ip}
RC=$?
if [ "$RC" -eq 0 ] ; then exit 0; fi # success

if [[ "$LD_PRELOAD" == *"libfailmalloc.so"* ]]
then
	echo "* NOTE: This test was running under libfailmalloc.so; a failure is expected, we only care whether we got SIGSEGV or not"
	let SEGV_BASH_RC=128+11 # SEGV is 11; bash will XOR it with 128 and this will be RC of child that got SIGSEGV
	if [ "$RC" -ne "$SEGV_BASH_RC" ]
	then
		echo "* SUCCESS! RC was $RC; we consider it as a success because this RC is not related to SIGSEGV (a standard failure is expected since we run under libfailmalloc.so)"
		RC=0 # consider it as success
	else
		echo "* FAILURE! Child got SIGSEGV (you may consider cleaning core files)"
	fi
fi
exit $RC


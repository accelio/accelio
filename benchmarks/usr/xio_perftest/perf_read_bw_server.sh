#!/bin/bash


export LD_LIBRARY_PATH=../../../src/usr/

# Arguments Check
trans="rdma"
if [ $# -eq 1 ]; then
	trans=$1
fi

intf1=192.168.1.66
intf2=192.168.1.66
intf_name=ib0

#single port server 
#./xio_read_bw -c 8 -n 8 -r ${trans} -w "192.168.40.46:1234;192.168.40.46:1235;192.168.40.46:1236;192.168.40.46:1237;192.168.40.46:1238;192.168.40.46:1239;192.168.40.46:1240;192.168.40.46:1241" -t 100

#dual port server 
./xio_read_bw -c 8 -n 8 -r ${trans} -w "$intf1:1234;$intf2:1235;$intf1:1236;$intf2:1237;$intf1:1238;$intf2:1239;$intf1:1240;$intf2:1241" -t 100


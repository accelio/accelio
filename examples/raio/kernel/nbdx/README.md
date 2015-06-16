NBDX
====

Accelio based network block device.

1. General
==========

NBDX is a network block device over Accelio framework. NBDX exploits the
advantages of the multi-queue implementation in the block layer as well as
the accelio acceleration facilities to provide fast IO to a remote device.
NBDX translates IO operations to libaio submit operations to the remote device.

2. NBDX Prerequisites
=====================

Prior to installing the nbdx package, the following prerequisites are required:

- Accelio
    1.1 version and above

- Kernel
    3.13.1 and above

3. Building and installation
============================

Install nbdx by following steps:

  - auto-generate (autoconf)
    $ ./autogen.sh
  - configure build
    $ ./configure
  - compile
    $ make
  - install
    $ sudo make install

4. HOWTO
========

The following example creates block device vs. remote nbdx server using Accelio
transport services.

	1. nbdx server steps:
		- create a file that would be exposed as a block device to nbdx client
		  at <device_path>
		- run ./nbdx_server <server_ip> <port>

	2. nbdx client steps:
		$ modprobe nbdx
		$ nbdxadm -o create_host -i <host_id> -p <server_ip:port>
		$ nbdxadm -o create_device -i <host_id> -d <device_id> -f <file_path>

In this stage, after the login and initialize stages are finished,
a nbdx type block device (/dev/nbdx<device_id>) is available and ready for data transfer.


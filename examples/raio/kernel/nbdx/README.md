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

- Kernel
    3.13.1 and above

3. Building and installation
============================

Install accelio userspace modules by following steps:

  - cd to accelio root directory
    $cd <accelio_root>
  - auto-generate (autoconf)
    $ ./autogen.sh
  - configure build
    $ ./configure --prefix=/opt/xio
  - compile
    $ make
  - install
    $ sudo make install


Install accelio kernel modules by following steps:

  - cd to accelio root directory
    $cd <accelio_root>
  - auto-generate (autoconf)
    $ ./autogen.sh
  - configure build
    $ ./configure --enable-kernel-module --prefix=/opt/xio
  - compile
    $ make
  - install
    $ sudo make install

4. HOWTO
========

The following example creates block device vs. remote raio server using Accelio
transport services.

	1. raio server steps:
		- create a file that would be exposed as a block device to nbdx client
		  at <device_path>
		- run taskset -c <cpu> /opt/xio/bin/raio_server <server_ip> <port> cpusmask>

	2. nbdx client steps:
		$ mount -t configfs none /sys/kernel/config
		$ modprobe nbdx
		$ nbdxadm -o create_host -i <host_id> -p <server_ip:port>
		$ nbdxadm -o create_device -i <host_id> -d <device_id> -f <file_path>

In this stage, after the login and initialize stages are finished,
a nbdx type block device (/dev/nbdx<device_id>) is available and ready for data transfer.


# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include -I$(top_srcdir)/tests/usr/common -I$(top_srcdir)/tests/portable/direct_rdma_test -I$(top_srcdir)/tests/portable @AM_CFLAGS@

AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lrt \
	     -L$(top_builddir)/src/usr/

COMMON_TEST_LD = $(top_builddir)/tests/usr/common

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = xio_rdma_client \
	       xio_rdma_server

# list of sources for the 'xio_perftest' binary
xio_rdma_client_SOURCES =  xio_rdma_client.c xio_rdma_common_usr.c

xio_rdma_server_SOURCES =  xio_rdma_server.c xio_rdma_common_usr.c

# the additional libraries needed to link xio_client
xio_rdma_client_LDADD = $(COMMON_TEST_LD)/libtestcommon.la  $(AM_LDFLAGS)
xio_rdma_server_LDADD = $(COMMON_TEST_LD)/libtestcommon.la  $(AM_LDFLAGS)

EXTRA_DIST = xio_msg.h

###############################################################################

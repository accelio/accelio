# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include -I$(top_srcdir)/tests/usr/common @AM_CFLAGS@

AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lrt \
	     -L$(top_builddir)/src/usr/

COMMON_TEST_LD = $(top_builddir)/tests/usr/common

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = xio_bidi_client \
	       xio_bidi_server

# list of sources for the 'xio_perftest' binary
xio_bidi_client_SOURCES =  xio_bidi_client.c

xio_bidi_server_SOURCES =  xio_bidi_server.c

# the additional libraries needed to link xio_client
xio_bidi_client_LDADD = $(COMMON_TEST_LD)/libtestcommon.la  $(AM_LDFLAGS)
xio_bidi_server_LDADD = $(COMMON_TEST_LD)/libtestcommon.la  $(AM_LDFLAGS)

EXTRA_DIST = xio_msg.h

###############################################################################

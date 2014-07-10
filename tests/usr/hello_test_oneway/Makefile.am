# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/usr/common @AM_CFLAGS@

AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lrt \
	     -L$(top_builddir)/src/usr/

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = xio_oneway_client \
	       xio_oneway_server
	
# list of sources for the 'xio_perftest' binary
xio_oneway_client_SOURCES =  ../common/xio_msg.c	\
			     ../common/xio_test_utils.c	\
			     xio_oneway_client.c		
		
xio_oneway_server_SOURCES =  ../common/xio_msg.c	\
			     ../common/xio_test_utils.c	\
			     xio_oneway_server.c		
	

# the additional libraries needed to link xio_oneway_client
xio_oneway_client_LDADD = 	$(AM_LDFLAGS)
xio_oneway_server_LDADD = 	$(AM_LDFLAGS)

EXTRA_DIST = xio_msg.h	

###############################################################################

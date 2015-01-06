# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include @AM_CFLAGS@

AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lpthread \
	     -L$(top_builddir)/src/usr/

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = xio_mt_client \
	       xio_mt_server

# list of sources for the 'xio_mt_client' binary
xio_mt_client_SOURCES =  xio_mt_client.c

# list of sources for the 'xio_mt_client' binary
xio_mt_server_SOURCES =  xio_mt_server.c


# the additional libraries needed to link xio_client
# xio_mt_client_LDADD = $(AM_LDFLAGS)
# xio_mt_server_LDADD = $(AM_LDFLAGS)

# EXTRA_DIST = xio_msg.h

###############################################################################

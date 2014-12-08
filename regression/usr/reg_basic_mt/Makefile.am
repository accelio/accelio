# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include -I$(top_srcdir)/regression/usr/common/ @AM_CFLAGS@

AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lrt -lpthread \
	     -L$(top_builddir)/src/usr/

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = reg_basic_mt
	
reg_basic_mt_SOURCES =  reg_basic_mt_server.c \
		        reg_basic_mt_client.c \
		        reg_basic_mt.c

# the additional libraries needed to link xio_client
###############################################################################

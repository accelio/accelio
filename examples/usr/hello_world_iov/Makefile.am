# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include @AM_CFLAGS@

AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lrt \
	     -L$(top_builddir)/src/usr/

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = xio_client \
	       xio_server
	
# list of sources for the 'xio_perftest' binary
xio_client_SOURCES =  xio_client.c		
		
xio_server_SOURCES =  xio_server.c		
	

# the additional libraries needed to link xio_client
#xio_client_LDADD = 	$(AM_LDFLAGS)
#xio_server_LDADD = 	$(AM_LDFLAGS)

#EXTRA_DIST = xio_msg.h	

###############################################################################

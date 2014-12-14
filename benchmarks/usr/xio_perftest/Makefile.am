# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include @AM_CFLAGS@

AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lrt -lpthread \
	     -L$(top_builddir)/src/usr/

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)

bin_PROGRAMS = xio_read_lat \
	       xio_read_bw

# list of sources for the 'xio_perftest' binary
xio_perftest_INCLUDES = xio_perftest.h			\
		       xio_perftest_parameters.h	\
		       xio_prerftest_resources.h	\
		       xio_prerftest_communication.h	\
		       xio_msg.h			\
		       get_clock.h

xio_read_lat_SOURCES =  $(xio_perftest_INCLUDES)	\
			xio_msg.c			\
		        xio_perftest_client.c		\
		        xio_perftest_server.c		\
		        xio_perftest_parameters.c	\
		        xio_perftest_communication.c	\
		        xio_perftest.c			\
			get_clock.c


xio_read_lat_CFLAGS = $(AM_CFLAGS) -DVERB_READ -DTEST_LAT 


xio_read_bw_SOURCES  =  $(xio_perftest_INCLUDES)	\
			xio_msg.c			\
		        xio_perftest_client.c		\
		        xio_perftest_server.c		\
		        xio_perftest_parameters.c	\
		        xio_perftest_communication.c	\
		        xio_perftest.c			\
			get_clock.c

xio_read_bw_CFLAGS = $(AM_CFLAGS) -DVERB_READ -DTEST_BW


###############################################################################

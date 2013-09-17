# this is example-file: src/Makefile.am

# additional include paths necessary to compile the C library
AM_CFLAGS = -fPIC -DPIC  				\
	    -I$(top_srcdir)/src/usr -I$(top_srcdir)/src/common -I$(top_srcdir)/include \
	    @AM_CFLAGS@

###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
#lib_LIBRARIES = libxio.a
bin_PROGRAMS = libxio.so

# where to install the headers on the system
libxioincdir = $(includedir)/xio/

# the list of header files that belong to the library (to be installed later)
libxioinc_HEADERS = $(top_srcdir)/include/libxio.h 

# the sources to add to the library and to add to the source distribution
libxio_so_SOURCES =	$(libxioinc_HEADERS)		\
			xio_init.c			\
			get_clock.c			\
			xio_rdma_mempool.c		\
			xio_rdma_verbs.c		\
			xio_rdma_management.c		\
			xio_rdma_datapath.c		\
			xio_ev_loop.c			\
			xio_log.c			\
			xio_mem.c			\
			xio_task.c			\
			xio_context.c			\
			../common/xio_options.c		\
			../common/xio_error.c		\
			../common/xio_utils.c		\
			../common/xio_server.c		\
			../common/xio_session.c		\
			../common/xio_sessions_store.c	\
			../common/xio_conn.c		\
			../common/xio_conns_store.c	\
			../common/xio_transport.c	\
			../common/xio_connection.c
	
				
libxio_so_LDFLAGS = -shared -rdynamic	 		\
		      -lrdmacm -libverbs -lrt -ldl
libxio_so_LDADD = $(AM_LDFLAGS)

EXTRA_DIST = 		libxio.map      		\
	     		libxio.spec.in
				
###############################################################################

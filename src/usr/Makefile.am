# this is example-file: src/Makefile.am

# additional include paths necessary to compile the C library
AM_CFLAGS = -fPIC -DPIC  				\
	    -I$(top_srcdir)/src/usr -I$(top_srcdir)/src/common -I$(top_srcdir)/include \
	    @AM_CFLAGS@

###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
lib_LTLIBRARIES = libxio.la

# where to install the headers on the system
libxio_includedir = $(includedir)/xio/

# the list of header files that belong to the library (to be installed later)
libxio_include_HEADERS = $(top_srcdir)/include/libxio.h  \
			 $(top_srcdir)/include/xio_user.h 


libxio_headers = 	./get_clock.h 				\
			./xio_log.h				\
			./xio_mem.h				\
			./xio_os.h				\
			./xio_rdma_mempool.h			\
			./xio_rdma_transport.h			\
			./xio_rdma_utils.h			\
			./xio_tls.h				\
			../common/xio_common.h			\
			../common/xio_connection.h		\
			../common/xio_conn.h			\
			../common/xio_conns_store.h		\
			../common/xio_context.h			\
			../common/xio_hash.h			\
			../common/xio_mbuf.h			\
			../common/xio_msg_list.h		\
			../common/xio_protocol.h		\
			../common/xio_server.h			\
			../common/xio_session.h			\
			../common/xio_sessions_store.h		\
			../common/xio_observer.h		\
			../common/xio_task.h			\
			../common/xio_transport.h		\
			../common/sys/hashtable.h		\
			./linux/atomic.h 			\
			./linux/kernel.h			\
			./linux/kref.h				\
			./linux/list.h				\
			./linux/printk.h			\
			./linux/slab.h				\
			./linux/usr.h				




# the sources to add to the library and to add to the source distribution
libxio_la_SOURCES =	$(libxio_headers)		\
			xio_init.c			\
			get_clock.c			\
			xio_rdma_mempool.c		\
			xio_rdma_utils.c		\
			xio_rdma_verbs.c		\
			xio_rdma_management.c		\
			xio_rdma_datapath.c		\
			xio_ev_loop.c			\
			xio_log.c			\
			xio_mem.c			\
			xio_task.c			\
			xio_usr_utils.c			\
			xio_tls.c			\
			xio_context.c			\
			./linux/hexdump.c		\
			../common/xio_options.c		\
			../common/xio_error.c		\
			../common/xio_utils.c		\
			../common/xio_server.c		\
			../common/xio_session.c		\
			../common/xio_sessions_store.c	\
			../common/xio_observer.c	\
			../common/xio_conn.c		\
			../common/xio_conns_store.c	\
			../common/xio_transport.c	\
			../common/xio_connection.c
	
				
#libxio_la_LDFLAGS = -shared -rdynamic	 		\
#		      -lrdmacm -libverbs -lrt -ldl

libxio_la_LDFLAGS = -lnuma -lrdmacm -libverbs -lrt -lpthread 

#libxio_la_LIBADD = $(AM_LDFLAGS)

#EXTRA_DIST = 		libxio.map      		\
#	     		libxio.spec.in
				
###############################################################################

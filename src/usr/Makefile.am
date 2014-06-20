# this is example-file: src/Makefile.am

# additional include paths necessary to compile the C library
AM_CFLAGS = -fPIC -DPIC  			\
	    -I$(top_srcdir)/src/usr 		\
	    -I$(top_srcdir)/src/usr/xio		\
	    -I$(top_srcdir)/src/usr/rdma	\
	    -I$(top_srcdir)/src/common  	\
	    -I$(top_srcdir)/include		\
	    @AM_CFLAGS@

if HAVE_LD_VERSION_SCRIPT
    libxio_version_script = -Wl,--version-script=$(top_srcdir)/src/usr/libxio.map
else
    libxio_version_script =
endif


###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
lib_LTLIBRARIES = libxio.la

# where to install the headers on the system
libxio_includedir = $(includedir)/

# the list of header files that belong to the library (to be installed later)
libxio_include_HEADERS = $(top_srcdir)/include/libxio.h  \
			 $(top_srcdir)/include/xio_user.h 


libxio_headers = 	./xio/get_clock.h 			\
			./xio/xio_log.h				\
			./xio/xio_mem.h				\
			./xio/xio_os.h				\
			./xio/xio_tls.h				\
			./xio/xio_timers_list.h			\
			./xio/xio_ev_loop.h			\
			./rdma/xio_rdma_mempool.h		\
			./rdma/xio_rdma_transport.h		\
			./rdma/xio_rdma_utils.h			\
			../common/xio_workqueue.h		\
			../common/xio_workqueue_priv.h		\
			../common/xio_common.h			\
			../common/xio_connection.h		\
			../common/xio_nexus.h			\
			../common/xio_nexus_cache.h		\
			../common/xio_context.h			\
			../common/xio_hash.h			\
			../common/xio_mbuf.h			\
			../common/xio_msg_list.h		\
			../common/xio_protocol.h		\
			../common/xio_server.h			\
			../common/xio_session.h			\
			../common/xio_session_priv.h		\
			../common/xio_sessions_cache.h		\
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
			../../version.c			\
			./xio/xio_init.c		\
			./xio/get_clock.c		\
			./xio/xio_ev_loop.c		\
			./xio/xio_log.c			\
			./xio/xio_mem.c			\
			./xio/xio_task.c		\
			./xio/xio_usr_utils.c		\
			./xio/xio_tls.c			\
			./xio/xio_context.c		\
			./xio/xio_workqueue.c		\
			./rdma/xio_rdma_mempool.c	\
			./rdma/xio_rdma_utils.c		\
			./rdma/xio_rdma_verbs.c		\
			./rdma/xio_rdma_management.c	\
			./rdma/xio_rdma_datapath.c	\
			../common/xio_options.c		\
			../common/xio_error.c		\
			../common/xio_utils.c		\
			../common/xio_server.c		\
			../common/xio_session.c		\
			../common/xio_session_server.c	\
			../common/xio_session_client.c	\
			../common/xio_sessions_cache.c	\
			../common/xio_observer.c	\
			../common/xio_nexus.c		\
			../common/xio_nexus_cache.c	\
			../common/xio_transport.c	\
			../common/xio_connection.c	
	
				
#libxio_la_LDFLAGS = -shared -rdynamic	 		\
#		      -lrdmacm -libverbs -lrt -ldl

libxio_la_LDFLAGS = -lnuma -lrdmacm -libverbs -lrt -lpthread \
		     $(libxio_version_script)

libxio_la_DEPENDENCIES =  $(top_srcdir)/src/usr/libxio.map

#libxio_la_LIBADD = $(AM_LDFLAGS)

#EXTRA_DIST = 		libxio.map      		\
#	     		libxio.spec.in
				
###############################################################################

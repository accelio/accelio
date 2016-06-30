# this is example-file: src/Makefile.am

# additional include paths necessary to compile the C library

if HAVE_INFINIBAND_VERBS
    libxio_rdma_srcdir = -I$(top_srcdir)/src/usr/transport/rdma
    libxio_rdma_headers = ./transport/rdma/xio_rdma_transport.h   \
			  ./transport/rdma/xio_rdma_utils.h
    libxio_rdma_sources = ./transport/rdma/xio_rdma_utils.c       \
                          ./transport/rdma/xio_rdma_verbs.c       \
                          ./transport/rdma/xio_rdma_management.c  \
                          ./transport/rdma/xio_rdma_datapath.c
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_srcdir =
    libxio_rdma_headers =
    libxio_rdma_sources =
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -fPIC -DPIC  			\
	    -I$(top_srcdir)/src/libxio_os/linuxapp	\
	    -I$(top_srcdir)/src/usr 		\
	    -I$(top_srcdir)/src/usr/xio		\
	    -I$(top_srcdir)/src/usr/transport	\
	    $(libxio_rdma_srcdir)		\
	    -I$(top_srcdir)/src/usr/transport/tcp	\
	    -I$(top_srcdir)/src/common  	\
	    -I$(top_srcdir)/include		\
	    @AM_CFLAGS@

if HAVE_LD_VERSION_SCRIPT
    libxio_version_script = -Wl,--version-script=$(top_srcdir)/src/usr/libxio.map
else
    libxio_version_script =
endif

install-exec-hook:
	@runner=`whoami` ; \
        if test $$runner != "root" ; \
	then \
		echo "You are not root. run the following manualy:"; \
		echo "echo \"$(libdir)\" > /etc/ld.so.conf.d/libxio.conf"; \
		echo "/sbin/ldconfig"; \
	else \
		echo "You are root" ; \
		echo "$(libdir)" > $(DESTDIR)/etc/ld.so.conf.d/libxio.conf ; \
		/sbin/ldconfig; \
	fi

###############################################################################
# THE LIBRARIES TO BUILD
###############################################################################

# the library names to build (note we are building static libs only)
lib_LTLIBRARIES = libxio.la

# where to install the headers on the system
libxio_includedir = $(includedir)/

# the list of header files that belong to the library (to be installed later)
libxio_include_HEADERS = $(top_srcdir)/include/libxio.h  	\
			 $(top_srcdir)/include/xio_base.h	\
			 $(top_srcdir)/include/xio_user.h	\
			 $(top_srcdir)/include/xio_predefs.h


libxio_headers = 	./xio/get_clock.h 			\
			./xio/xio_log.h				\
			./xio/xio_mem.h				\
			./xio/xio_os.h				\
			./xio/xio_tls.h				\
			./xio/xio_timers_list.h			\
			./xio/xio_ev_loop.h			\
			./transport/xio_mempool.h		\
			./transport/xio_usr_transport.h		\
			$(libxio_rdma_headers)			\
			./transport/tcp/xio_tcp_transport.h	\
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
			../common/xio_idr.h			\
			../common/xio_observer.h		\
			../common/xio_task.h			\
			../common/xio_sg_table.h		\
			../common/xio_objpool.h			\
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
			./xio/xio_netlink.c		\
			./xio/xio_workqueue.c		\
			./xio/xio_sg_iov.c		\
			./xio/xio_sg_iovptr.c		\
			./xio/xio_sg_table.c		\
			$(libxio_rdma_sources)		\
			./transport/tcp/xio_tcp_management.c	\
			./transport/tcp/xio_tcp_datapath.c	\
			./transport/xio_mempool.c	\
			./transport/xio_usr_transport.c	\
			../common/xio_objpool.c		\
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
			../common/xio_idr.c		\
			../common/xio_transport.c	\
			../common/xio_connection.c

#libxio_la_LDFLAGS = -shared -rdynamic	 		\
#		      -lrdmacm -libverbs -lrt -ldl

libxio_la_LDFLAGS = -lnuma $(libxio_rdma_ldflags) -ldl -lrt -lpthread \
		     $(libxio_version_script)

libxio_la_DEPENDENCIES =  $(top_srcdir)/src/usr/libxio.map

#libxio_la_LIBADD = $(AM_LDFLAGS)

#EXTRA_DIST = 		libxio.map      		\
#	     		libxio.spec.in

###############################################################################

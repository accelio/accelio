# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include		\
	    -I$(top_srcdir)/examples/raio/usr/libraio @AM_CFLAGS@
AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lpthread -laio \
	     -L$(top_builddir)/src/usr/

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
lib_LTLIBRARIES = libraio.la
bin_PROGRAMS = raio_client 			\
	       raio_server

# where to install the headers on the system
libraio_includedir = $(includedir)/

# the list of header files that belong to the library (to be installed later)
libraio_include_HEADERS = $(top_srcdir)/examples/raio/usr/libraio/libraio.h


libraio_common_headers   =  ./usr/libraio/raio_msg_pool.h		\
		     	    ./usr/libraio/raio_buffer.h			\
		     	    ./usr/libraio/raio_command.h		\
		     	    ./usr/libraio/raio_utils.h

libraio_la_SOURCES = $(libraio_include_HEADERS) 			\
		     $(libraio_common_headers)		      		\
		     ./usr/libraio/raio_msg_pool.c			\
		     ./usr/libraio/raio_utils.c				\
		     ./usr/libraio/raio_api.c

libraio_la_LDFLAGS = -lxio $(libxio_rdma_ldflags) -laio -lrt -lpthread \
		     -L$(top_builddir)/src/usr/

# list of sources for the binary
raio_server_SOURCES = ./usr/server/bitset.c				\
		      ./usr/server/raio_server.c			\
		      ./usr/server/raio_handlers.c			\
		      ./usr/server/raio_bs.c 				\
		      ./usr/server/raio_bs_null.c			\
		      ./usr/server/raio_bs_aio.c
raio_server_DEPENDENCIES = libraio.la

raio_client_SOURCES = ./usr/client/raio_client.c			\
		      ./usr/client/get_clock.c
raio_client_DEPENDENCIES = libraio.la


#libraio_la_LDFLAGS = -shared -rdynamic	 	\
#		      -lxio -lrdmacm -libverbs -laio -lrt -ldl
#libraio_la_LIBADD = $(AM_LDFLAGS)

# the additional libraries needed to link raio_server
#raio_server_LDADD = libraio.a $(AM_LDFLAGS)
raio_client_LDADD = -lraio -L$(top_builddir)/examples/raio/usr/libraio $(AM_LDFLAGS)
raio_server_LDADD = -lraio -L$(top_builddir)/examples/raio/usr/libraio $(AM_LDFLAGS)

EXTRA_DIST =

###############################################################################

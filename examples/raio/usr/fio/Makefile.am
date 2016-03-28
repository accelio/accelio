# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -D_GNU_SOURCE -DFIO_INC_DEBUG -DPIC			    \
	    -include $(FIO_ROOT)/config-host.h 			    \
	    -Wall -O2 -g -shared -rdynamic -fPIC		    \
	    -I$(top_srcdir)/include/  		  		    \
	    -I$(top_srcdir)/examples/raio/usr/libraio	    	    \
	    -I$(FIO_ROOT)/					    \
	    -I$(FIO_ROOT)/engines/

#AM_LDFLAGS = -lraio -lxio -lrdmacm -libverbs -ldl -lrt -lpthread  \
#	     -L$(top_builddir)/src/usr/ -L$(top_builddir)/examples/usr/raio/


###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
lib_LTLIBRARIES = libraio_fio.la


# list of sources for the 'libraio_fio' shared library
libraio_fio_la_SOURCES = libraio.c

libraio_fio_la_LIBADD = -lraio -lxio $(libxio_rdma_ldflags) -lrt -ldl -lpthread  \
	     		-L$(top_builddir)/src/usr/ -L$(top_builddir)/examples/raio/


###############################################################################

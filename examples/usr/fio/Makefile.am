# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs

AM_CFLAGS = -D_GNU_SOURCE -DFIO_INC_DEBUG -DPIC			    \
	    -include ../config-host.h 				    \
	    -Wall -O2 -g -shared -rdynamic -fPIC		    \
	    -I$(top_srcdir)/include/  		  		    \
	    -I$(top_srcdir)/examples/usr/raio/			    \
	    -I$(FIO_ROOT)/engines/

#AM_LDFLAGS = -lraio -lxio -lrdmacm -libverbs -ldl -lrt -lpthread  \
#	     -L$(top_srcdir)/src/usr/ -L$(top_srcdir)/examples/usr/raio/


###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
lib_LTLIBRARIES = libraio_fio.la


# list of sources for the 'libraio_fio' shared library
libraio_fio_la_SOURCES = libraio.c

libraio_fio_la_LIBADD = -lraio -lxio -lrdmacm -libverbs -lrt -ldl -lpthread  \
	     		-L$(top_srcdir)/src/usr/ -L$(top_srcdir)/examples/usr/raio/


###############################################################################

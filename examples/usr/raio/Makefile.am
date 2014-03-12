# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include @AM_CFLAGS@
AM_LDFLAGS = -lxio -libverbs -lrdmacm -lrt -lpthread -laio \
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
libraio_include_HEADERS = $(top_srcdir)/examples/usr/raio/libraio.h 

libraio_headers   =  get_clock.h		\
		     msg_pool.h			\
		     raio_bs.h			\
		     raio_buffer.h		\
		     raio_command.h		\
		     raio_handlers.h		\
		     raio_utils.h

libraio_la_SOURCES = $(libraio_include_HEADERS) 	\
		     $(libraio_headers)		      	\
		     msg_pool.c			      	\
		     raio_utils.c			\
		     raio_api.c		

	
# list of sources for the binary
raio_server_SOURCES = raio_server.c		\
		      raio_handlers.c		\
		      raio_bs.c 		\
		      raio_bs_null.c		\
		      raio_bs_aio.c		

raio_client_SOURCES = raio_client.c		\
		      get_clock.c

libraio_la_LDFLAGS = -lxio -lrdmacm -libverbs -laio -lrt -lpthread \
	     	     -L$(top_builddir)/src/usr/ 

#libraio_la_LDFLAGS = -shared -rdynamic	 	\
#		      -lxio -lrdmacm -libverbs -laio -lrt -ldl
#libraio_la_LIBADD = $(AM_LDFLAGS)

# the additional libraries needed to link raio_server
#raio_server_LDADD = libraio.a $(AM_LDFLAGS)
raio_client_LDADD = -lraio -L$(top_builddir)/examples/usr/raio/ $(AM_LDFLAGS)
raio_server_LDADD = -lraio -L$(top_builddir)/examples/usr/raio/ $(AM_LDFLAGS)

EXTRA_DIST =

###############################################################################

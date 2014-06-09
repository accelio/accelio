# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
AM_CFLAGS = -I$(top_srcdir)/include @AM_CFLAGS@

AM_LDFLAGS = -lxio -libverbs -lrdmacm -lrt \
	     -L$(top_builddir)/src/usr/

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = xioclntd \
	       xiosrvd
	
# list of sources
xioclntd_SOURCES =  xioclntd.c		
		
xiosrvd_SOURCES =  xiosrvd.c		
	

###############################################################################

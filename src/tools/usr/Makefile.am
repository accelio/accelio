
# additional include pathes necessary to compile the C programs
AM_CFLAGS = -I$(top_srcdir)/include @AM_CFLAGS@ \
	    -I$(top_srcdir)/src/common		\
	    -I$(top_srcdir)/src/usr		\
	    -I$(top_srcdir)/src/usr/transport	\
	    -I$(top_srcdir)/src/usr/transport/rdma	\
	    -I$(top_srcdir)/src/usr/xio		

AM_LDFLAGS = -L$(top_builddir)/src/usr/

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = xio_mem_usage
	
# list of sources for the 'xio_mem_usage' binary
xio_mem_usage_SOURCES =  xio_mem_usage.c		
		
###############################################################################

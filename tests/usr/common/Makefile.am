# this is example file: examples/hello_world/Makefile.am

# additional include pathes necessary to compile the C programs
AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include @AM_CFLAGS@

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
noinst_LTLIBRARIES = libtestcommon.la

nodist_libtestcommon_la_SOURCES = xio_msg.c 	\
				  xio_intf.c	\
				  xio_thread.c	\
				  xio_test_utils.c


###############################################################################

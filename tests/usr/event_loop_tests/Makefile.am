
# additional include pathes necessary to compile the C programs
if HAVE_INFINIBAND_VERBS
    libxio_rdma_ldflags = -lrdmacm -libverbs
else
    libxio_rdma_ldflags =
endif

AM_CFLAGS = -DPIC -fPIC -I$(top_srcdir)/include -I$(top_srcdir)/tests/usr/common @AM_CFLAGS@

AM_LDFLAGS = -lxio $(libxio_rdma_ldflags) -lrt \
	     -L$(top_builddir)/src/usr/

COMMON_TEST_LD = $(top_builddir)/tests/usr/common

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = event_loop_tests

# list of sources for the 'xio_perftest' binary
event_loop_tests_SOURCES =  event_loop_tests.c

# the additional libraries needed to link event_loop_tests
event_loop_tests_LDADD = $(COMMON_TEST_LD)/libtestcommon.la $(AM_LDFLAGS)

###############################################################################

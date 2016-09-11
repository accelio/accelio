# this is example-file: configure.ac

# initial information about the project
AC_INIT([libxio],[1.0],[info@accelio.org], [], [http://accelio.org])

# automake initialization (mandatory) and check for minimal automake API version 1.11
AM_INIT_AUTOMAKE([subdir-objects 1.11])

# Checks for language
AC_LANG_C

# Checks for programs
LT_INIT
AC_PROG_LIBTOOL

# check for C compiler and the library compiler
AC_PROG_CC
AM_PROG_CC_C_O

AM_SILENT_RULES([yes])

# use the C compiler for the following checks
AC_LANG([C])

##########################################################################
# rdma compilation support
##########################################################################
# usage: ./configure --enable-rdma=no
#
AC_MSG_CHECKING([whether to build with rdma])
AC_ARG_ENABLE([rdma],
	      [AS_HELP_STRING([--enable-rdma],
			      [enable rdma transport - default:yes ])],
			       [enable_rdma=$enableval],
			       [enable_rdma=yes])
AC_MSG_RESULT([$enable_rdma])

# Checks for header files.
if test "$enable_rdma" = "yes"; then
	AC_CHECK_HEADERS([infiniband/verbs.h rdma/rdma_cma.h],
			 [mypj_found_verbs_headers=yes; break;])
else
	mypj_found_verbs_headers=no
fi

AC_CHECK_HEADERS([numa.h],
		 [mypj_found_numa_headers=yes; break;])

AC_CHECK_HEADERS([event2/event.h],
		 [mypj_found_event_headers=yes; break;])


AM_CONDITIONAL(HAVE_INFINIBAND_VERBS, test "x$mypj_found_verbs_headers" = "xyes")

AS_IF([test "x$mypj_found_numa_headers" != "xyes"],
      [AC_MSG_ERROR([Unable to find the numactl-devel header files])])
# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

AC_CHECK_LIB(numa, numa_available)

#
# Check for Contiguous Pages support
#
if test "$enable_rdma" = "yes"; then
AC_CHECK_DECLS(IBV_EXP_ACCESS_ALLOCATE_MR,
              [AC_DEFINE([HAVE_MPAGES_EXP], 1, [Contiguous pages support, experimental]) havempages="yes"],
              [],
              [[#include <infiniband/verbs.h>]])

AC_CHECK_DECLS(IBV_DEVICE_MR_ALLOCATE,
              [AC_DEFINE([HAVE_MPAGES], 1, [Contiguous pages support]) havempages="yes"],
              [],
              [[#include <infiniband/verbs.h>]])

AS_IF([test "x$havempages" != "xyes"],
        [AC_MSG_WARN([Contiguous pages not supported.])])
fi

##########################################################################
# perf support
##########################################################################
# usage: ./configure --enable-perf=yes
#
AC_MSG_CHECKING([whether to enable profiler perf tool flags])
AC_ARG_ENABLE([perf],
	      [AS_HELP_STRING([--enable-perf],
			      [enable perf profiling])],
			       [enable_perf="$enableval"],
			       [enable_perf=no])
AC_MSG_RESULT([$enable_perf])

if test "$enable_perf" = "yes"; then
	AM_CFLAGS="$AM_CFLAGS -fno-omit-frame-pointer"
fi

##########################################################################
# debug compilation support
##########################################################################
# usage: ./configure --enable-debug=yes
#
AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
	      [AS_HELP_STRING([--enable-debug],
			      [enable debug data generation])],
			       [enable_debug="$enableval"],
			       [enable_debug=no])
AC_MSG_RESULT([$enable_debug])

if test "$enable_debug" = "yes"; then
	AC_DEFINE([DEBUG],[],[Debug Mode])
	AM_CFLAGS="$AM_CFLAGS -g -ggdb -Wall -Werror -Wdeclaration-after-statement \
		  -Wsign-compare -Wc++-compat \
		   -fno-omit-frame-pointer -O0 -D_REENTRANT -D_GNU_SOURCE"
else
	AC_DEFINE([NDEBUG],[],[No-debug Mode])
	AM_CFLAGS="$AM_CFLAGS -g -ggdb -Wall -Werror -Wpadded -Wdeclaration-after-statement \
		  -Wsign-compare -Wc++-compat \
		  -O3 -D_REENTRANT -D_GNU_SOURCE"
fi

AC_CACHE_CHECK(whether ld accepts --version-script, ac_cv_version_script,
    if test -n "`$LD --help < /dev/null 2>/dev/null | grep version-script`"; then
        ac_cv_version_script=yes
    else
        ac_cv_version_script=no
    fi)

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$ac_cv_version_script" = "yes")

##########################################################################
# performance compilation support
##########################################################################
# usage: ./configure --disable-extra-checks=yes
#
AC_MSG_CHECKING([perform extra checks for messages but reduces performance - use carefully])
AC_ARG_ENABLE([extra_checks],
	      [AS_HELP_STRING([--enable-extra-checks],
			      [enable extra checks for messages validity - default yes])],
			       [enable_extra_checks="$enableval"],
			       [enable_extra_checks=yes])
AC_MSG_RESULT([$enable_extra_checks])

if test "$enable_extra_checks" != "no"; then
	AM_CFLAGS="$AM_CFLAGS -DXIO_CFLAG_EXTRA_CHECKS"
fi

##########################################################################
# statistics counters emission support
##########################################################################
# usage: ./configure --enable-stat-counters=yes
#
AC_MSG_CHECKING([enable statistic counters emission via netlink socket])
AC_ARG_ENABLE([stat_counters],
	      [AS_HELP_STRING([--enable-stat-counters],
			      [enable statistics counters via netlink - default yes])],
			      [enable_statistics_counters="$enableval"],
			      [enable_statistics_counters=yes])
AC_MSG_RESULT([$enable_statistics_counters])

if test "$enable_statistics_counters" != "no"; then
	AM_CFLAGS="$AM_CFLAGS -DXIO_CFLAG_STAT_COUNTERS"
fi

##########################################################################
# debug thread safety support
##########################################################################
# usage: ./configure --enable-debug-thread-safety=yes
#
AC_MSG_CHECKING([EXPIRIMENTAL: checks if the application is thread safe when it comes to accelio callbacks and methods])
AC_ARG_ENABLE([debug-thread-safety],
	      [AS_HELP_STRING([--enable-debug-thread-safety],
			      [experimental:enable debug thread safety - default no])],
			      [enable_debug_thread_safety="$enableval"],
			      [enable_debug_thread_safety=no])
AC_MSG_RESULT([$enable_debug_thread_safety])

if test "$enable_debug_thread_safety" = "yes"; then
	AM_CFLAGS="$AM_CFLAGS -DXIO_THREAD_SAFE_DEBUG"
fi

##########################################################################
# enable shared receive queue (rdma)
##########################################################################
# usage: ./configure --enable-shared-receive-queue=yes
#
AC_MSG_CHECKING([enables shared receive queue support in rdma transport])
AC_ARG_ENABLE([shared-receive-queue],
	      [AS_HELP_STRING([--enable-shared-receive-queue],
			      [enable shared receive queue - default: no])],
			       [enable_shared_receive_queue="$enableval"],
			       [enable_shared_receive_queue=no])
AC_MSG_RESULT([$enable_shared_receive_queue])

if test "$enable_shared_receive_queue" = "yes"; then
	AM_CFLAGS="$AM_CFLAGS -DXIO_SRQ_ENABLE"
fi

##########################################################################
# raio compilation support
##########################################################################
# usage: ./configure --disable-raio-build
#
AC_MSG_CHECKING([whether to build with raio example library])
AC_ARG_ENABLE([raio_build],
	      [AS_HELP_STRING([--enable-raio-build],
			      [enable raio library generation - default:yes ])],
			       [enable_raio_build=$enableval],
			       [enable_raio_build=yes])
AC_MSG_RESULT([$enable_raio_build])

if test "$enable_raio_build" != "no"; then
AC_CHECK_HEADERS([libaio.h],
		 [mypj_found_aio_headers=yes; break;])
AS_IF([test "x$mypj_found_aio_headers" != "xyes"],
      [AC_MSG_ERROR([Unable to find the libaio-devel header files])])
fi

##########################################################################
# fio compilation support
##########################################################################
# usage: ./configure --enable-fio-build=yes
#
AC_MSG_CHECKING([whether to build with fio ioengine])
AC_ARG_ENABLE([fio_build],
	      [AS_HELP_STRING([--enable-fio-build],
			      [enable fio ioengine generation ])],
			       [enable_fio_build="$enableval"],
			       [enable_fio_build=no])
AC_MSG_RESULT([$enable_fio_build])

AM_CONDITIONAL([FIO_ROOT],[test "$FIO_ROOT" != 0])
AC_ARG_VAR([FIO_ROOT],[The root directory of the fio suite])
AC_SUBST([FIO_ROOT])

##########################################################################
AC_MSG_CHECKING([whether to build kernel module])
AC_ARG_ENABLE(kernel-module,
	[  --enable-kernel-module  Compile kernel module ],
	[enable_kernel_module="$enableval"],
	[enable_kernel_module=no])

AC_MSG_RESULT([$enable_kernel_module])

if test "$enable_kernel_module" != "no"; then
	AC_CONFIG_SUBDIRS([src/kernel/xio])
	AC_CONFIG_SUBDIRS([src/kernel/transport/rdma])
	AC_CONFIG_SUBDIRS([src/kernel/transport/tcp])
	AC_CONFIG_SUBDIRS([examples/kernel/hello_world])
	AC_CONFIG_SUBDIRS([examples/kernel/hello_world_mt])
	AC_CONFIG_SUBDIRS([tests/kernel/hello_test])
	AC_CONFIG_SUBDIRS([tests/kernel/hello_test_lat])
	AC_CONFIG_SUBDIRS([tests/kernel/hello_test_ow])
	if test "$enable_raio_build" == "yes"; then
		AC_CONFIG_SUBDIRS([examples/raio/kernel/nbdx])
	fi
else
	subdirs2="src/usr";
	subdirs2="$subdirs2 src/tools/usr/";
	subdirs2="$subdirs2 examples/usr/hello_world";
	subdirs2="$subdirs2 examples/usr/hello_world_mt";
	subdirs2="$subdirs2 examples/usr/hello_world_iov";
	subdirs2="$subdirs2 examples/usr/hello_world_daemon";

if test "$mypj_found_event_headers" == "yes"; then
	subdirs2="$subdirs2 examples/usr/hello_world_libevent";
fi
if test "$enable_raio_build" != "no"; then
	subdirs2="$subdirs2 examples/raio";
if test "$enable_fio_build" != "no"; then
	subdirs2="$subdirs2 examples/raio/usr/fio";
fi
fi
	subdirs2="$subdirs2 tests/usr/common";
	subdirs2="$subdirs2 tests/usr/hello_test";
	subdirs2="$subdirs2 tests/usr/hello_test_mt";
	subdirs2="$subdirs2 tests/usr/hello_test_bidi";
	subdirs2="$subdirs2 tests/usr/hello_test_lat";
	subdirs2="$subdirs2 tests/usr/hello_test_ow";
	subdirs2="$subdirs2 tests/usr/hello_test_oneway";
	subdirs2="$subdirs2 tests/usr/event_loop_tests";
if test "$enable_rdma" != "no"; then
	subdirs2="$subdirs2 tests/usr/direct_rdma_test";
fi
	subdirs2="$subdirs2 benchmarks/usr/xio_perftest";
	subdirs2="$subdirs2 regression/usr/reg_basic_mt";
fi

##########################################################################

##########################################################################
# add version.c uses strings to get GIT hash version
##########################################################################
if test -d "${GIT_DIR:-${ac_top_srcdir:-./}/.git}" ; then
	GITHEAD=`git describe --tags --long 2>/dev/null`
	if test -z ${GITHEAD} ; then
		GITHEAD=`git rev-parse HEAD`
	fi
	if test -n "`git diff-index -m --name-only HEAD`" ; then
		GITHEAD=${GITHEAD}-dirty
		fi
else
	GITHEAD=
fi
echo "const char XIO_GIT_HEAD@<:@@:>@ = \"GIT_VERSION: $GITHEAD\";" \/\* for use with strings \*\/ >version.c
echo "const char XIO_GIT_HEAD_STRING@<:@@:>@ = \"$GITHEAD\";" >>version.c
echo "const char XIO_VERSION_STRING@<:@@:>@ = \"accelio_$GITHEAD\";" >>version.c

AC_MSG_CHECKING([for git head])
AC_MSG_RESULT([$GITHEAD])
AC_DEFINE_UNQUOTED([XIO_GITHEAD], ["$GITHEAD"], [Git commit used to build xio library])




# distribute additional compiler and linker flags
# --> set these variables instead of CFLAGS or LDFLAGS
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LIBS])
AC_SUBST([subdirs2])


# files to generate via autotools (.am or .in source files)
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([Doxyfile])
AC_CONFIG_FILES([src/usr/Makefile])
AC_CONFIG_FILES([src/tools/usr/Makefile])
AC_CONFIG_FILES([examples/usr/hello_world/Makefile])
AC_CONFIG_FILES([examples/usr/hello_world_mt/Makefile])
AC_CONFIG_FILES([examples/usr/hello_world_iov/Makefile])
AC_CONFIG_FILES([examples/usr/hello_world_daemon/Makefile])
if test "$mypj_found_event_headers" == "yes"; then
	AC_CONFIG_FILES([examples/usr/hello_world_libevent/Makefile])
fi
AC_CONFIG_FILES([examples/raio/Makefile])
if test "$enable_fio_build" != "no"; then
AC_CONFIG_FILES([examples/raio/usr/fio/Makefile])
fi
AC_CONFIG_FILES([tests/usr/common/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_mt/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_bidi/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_lat/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_ow/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_oneway/Makefile])
AC_CONFIG_FILES([tests/usr/event_loop_tests/Makefile])
if test "$enable_rdma" != "no"; then
AC_CONFIG_FILES([tests/usr/direct_rdma_test/Makefile])
fi
AC_CONFIG_FILES([benchmarks/usr/xio_perftest/Makefile])
AC_CONFIG_FILES([regression/usr/reg_basic_mt/Makefile])

# generate the final Makefile etc.
AC_OUTPUT

# print warning if tests are enabled but gccxml not found
if test "$enable_fio_build" = "yes"; then
if (! test "$FIO_ROOT") ; then
AC_MSG_WARN([
*********************************************************************************
!!!!    There is a problem with the current configuration environment    !!!!

To run the tests of this package, the following variable(s) need to be defined :

FIO_ROOT  : The root directory of the fio package
	    installation:  git clone git://git.kernel.dk/fio.git. run make for
	    build
	    tested version: fio-2.1.1


The variables can be defined as environment variables (eg. with bash "export") or
passed to the configure command (e.g. ./configure FIO_ROOT=/opt/fio/ ).
The variables should point to the directory which contain
/engines,/examples,etcsubdirs.
*********************************************************************************
])
fi
fi

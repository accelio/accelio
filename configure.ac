# this is example-file: configure.ac

# initial information about the project
AC_INIT([libxio],[1.0],[libxio@accelio.org])
AM_INIT_AUTOMAKE

# Checks for language
AC_LANG_C

# Checks for programs
LT_INIT
AC_PROG_LIBTOOL

# check for C compiler and the library compiler
AC_PROG_CC
AM_PROG_CC_C_O

# automake initialisation (mandatory) and check for minimal automake API version 1.9
AM_INIT_AUTOMAKE([1.11])
AM_SILENT_RULES([yes])

# use the C compiler for the following checks
AC_LANG([C])

# Checks for header files.
AC_CHECK_HEADERS([infiniband/verbs.h rdma/rdma_cma.h],
		 [mypj_found_verbs_headers=yes; break;])

AC_CHECK_HEADERS([numa.h],
		 [mypj_found_numa_headers=yes; break;])


AS_IF([test "x$mypj_found_verbs_headers" != "xyes"],
      [AC_MSG_ERROR([Unable to find the infiniband header files])])
AS_IF([test "x$mypj_found_numa_headers" != "xyes"],
      [AC_MSG_ERROR([Unable to find the numactl-devel header files])])
# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

AC_CHECK_LIB(numa, numa_available)

##########################################################################
# perf support
##########################################################################
# usage: ./configure --enable-perf=yes
#
AC_MSG_CHECKING([whether to build with debug information])
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
		   -fno-omit-frame-pointer -O0 -D_REENTRANT -D_GNU_SOURCE"
else
	AC_DEFINE([NDEBUG],[],[No-debug Mode])
	AM_CFLAGS="$AM_CFLAGS -g -ggdb -Wall -Werror -Wpadded -Wdeclaration-after-statement \
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
	AC_CONFIG_SUBDIRS([src/kernel/rdma])
	AC_CONFIG_SUBDIRS([examples/kernel/hello_world])
	AC_CONFIG_SUBDIRS([examples/kernel/hello_world_mt])
fi

if test "$enable_kernel_module" != "no"; then
	subdirs2="src/kernel";
else
	subdirs2="src/usr";
	subdirs2="$subdirs2 examples/usr/hello_world";
	subdirs2="$subdirs2 examples/usr/hello_world_mt";
if test "$enable_raio_build" != "no"; then
	subdirs2="$subdirs2 examples/usr/raio";
if test "$enable_fio_build" != "no"; then
	subdirs2="$subdirs2 examples/usr/fio";
fi
fi
	subdirs2="$subdirs2 tests/usr/hello_test";
	subdirs2="$subdirs2 tests/usr/hello_test_mt";
	subdirs2="$subdirs2 tests/usr/hello_test_bidi";
	subdirs2="$subdirs2 tests/usr/hello_test_lat";
	subdirs2="$subdirs2 tests/usr/hello_test_oneway";
	subdirs2="$subdirs2 benchmarks/usr/xio_perftest";
fi

##########################################################################

##########################################################################
# add version.c uses strings to get GIT hash version
##########################################################################
if test -d "${GIT_DIR:-${ac_top_srcdir:-./}/.git}" ; then
	GITHEAD=`git describe 2>/dev/null`
	if test -z ${GITHEAD} ; then
		GITHEAD=`git rev-parse HEAD`
		echo "const char XIO_GIT_HEAD@<:@@:>@ = \"GIT_VERSION: $GITHEAD\";" \/\* for use with strings \*\/ >version.c
		echo "const char XIO_GIT_HEAD_STRING@<:@@:>@ = \"$GITHEAD\";" >>version.c
	fi
	if test -n "`git diff-index -m --name-only HEAD`" ; then
		GITHEAD=${GITHEAD}-dirty
		echo "const char XIO_GIT_HEAD@<:@@:>@ = \"GIT_VERSION: $GITHEAD\";" \/\* for use with strings \*\/ >version.c
		echo "const char XIO_GIT_HEAD_STRING@<:@@:>@ = \"$GITHEAD\";" >>version.c
	fi
else
	GITHEAD=
fi

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
AC_CONFIG_FILES([examples/usr/hello_world/Makefile])
AC_CONFIG_FILES([examples/usr/hello_world_mt/Makefile])
AC_CONFIG_FILES([examples/usr/raio/Makefile])
if test "$enable_fio_build" != "no"; then
AC_CONFIG_FILES([examples/usr/fio/Makefile])
fi
AC_CONFIG_FILES([tests/usr/hello_test/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_mt/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_bidi/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_lat/Makefile])
AC_CONFIG_FILES([tests/usr/hello_test_oneway/Makefile])
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

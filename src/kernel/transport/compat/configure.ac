AC_INIT([xio-kernel],[2.0],[libxio@accellio.org])

AC_PROG_INSTALL

runver=`uname -r`
bad_kernel_version=no
ENABLE_COMPAT_MODULE=y
# do not build against ofed until kernel module can be built out of kernel
# tree
KERNELCFLAGS=
KERNELMAKE_PARAMS=

kernelsrc=
kernelbuild=
AC_ARG_WITH(kernel,
	[  --with-kernel=PATH      Specify location of kernel source ],
	[kernelsrc="$withval"; kernelbuild="$withval"])
AC_ARG_WITH(kernel-build,
	[  --with-kernel-build=PATH Specify location of kernel build ],
	[kernelbuild="$withval"])
AC_ARG_ENABLE(kernel-module,
	[  --enable-kernel-module  Compile kernel module ])


#build against installed OFED
AC_MSG_CHECKING([if ofed installed])
MLNX_OFED=`if ofed_info 2>/dev/null | grep MLNX_OFED >/dev/null 2>/dev/null; then echo true; else echo false; fi`

if test "$MLNX_OFED" = "true"; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)

fi
if test -z "$enable_kernel_module" -a "$MLNX_OFED" = "true"; then
	ENABLE_COMPAT_MODULE=n
fi


if test "$ENABLE_COMPAT_MODULE" = y; then
	AC_MSG_CHECKING([kernel source directory])
	if test -z "$kernelsrc"; then
		kernelbuild=
		sourcelink=/lib/modules/${runver}/source
		buildlink=/lib/modules/${runver}/build

		if test -e $sourcelink; then
			kernelsrc=`(cd $sourcelink; /bin/pwd)`
		fi
		if test -e $buildlink; then
			kernelbuild=`(cd $buildlink; /bin/pwd)`
		fi
		if test -z "$kernelsrc"; then
			kernelsrc=$kernelbuild
		fi
		if test -z "$kernelsrc" -o -z "$kernelbuild"; then
			AC_MSG_RESULT([Not found])
			AC_MSG_ERROR([
	*** Please specify the location of the kernel source with
	*** the '--with-kernel=SRCDIR' option])
		fi
	fi
	AC_MSG_RESULT([$kernelsrc])
	AC_MSG_CHECKING([kernel build directory])
	AC_MSG_RESULT([$kernelbuild])

	AC_MSG_CHECKING([kernel source version])
	if test -r $kernelbuild/include/linux/version.h && fgrep -q UTS_RELEASE $kernelbuild/include/linux/version.h; then
		kernsrcver=`(echo "#include <linux/version.h>"; echo "kernsrcver=UTS_RELEASE") | cpp -I $kernelbuild/include | grep "^kernsrcver=" | cut -d \" -f 2`
	elif test -r $kernelbuild/include/linux/utsrelease.h && fgrep -q UTS_RELEASE $kernelbuild/include/linux/utsrelease.h; then
		kernsrcver=`(echo "#include <linux/utsrelease.h>"; echo "kernsrcver=UTS_RELEASE") | cpp -I $kernelbuild/include | grep "^kernsrcver=" | cut -d \" -f 2`
	elif test -r $kernelbuild/include/generated/utsrelease.h && fgrep -q UTS_RELEASE $kernelbuild/include/generated/utsrelease.h; then
		kernsrcver=`(echo "#include <generated/utsrelease.h>"; echo "kernsrcver=UTS_RELEASE") | cpp -I $kernelbuild/include | grep "^kernsrcver=" | cut -d \" -f 2`
	fi
	if test -z "$kernsrcver"; then
		AC_MSG_RESULT([Not found])
		AC_MSG_ERROR([
	*** Cannot determine the version of the linux kernel source. Please
	*** prepare the kernel before running this script])
	fi
	AC_MSG_RESULT([$kernsrcver])
	kmoduledir=${INSTALL_MOD_PATH}/lib/modules/$kernsrcver
	AC_SUBST(kernelsrc)
	AC_SUBST(kmoduledir)

	if echo "$kernsrcver" | egrep -q ["^(2.4|2.6.[0-8]([^0-9]|\$))"]; then
		bad_kernel_version=yes
		AC_MSG_NOTICE([
NOTE:    Disabled building the kernel module, because this release only
NOTE:    supports Linux versions 2.6.9 or later.  You can use the kernel
NOTE:    module from an earlier COMPAT release with the library from this
NOTE:    release.])
	else
		compat_configured=no
		kernel_autoconf=$kernelbuild/include/linux/autoconf.h
		AC_MSG_CHECKING([if COMPAT is configured in the kernel])
		if test -f $kernel_autoconf; then
			if grep -q "^#define CONFIG_COMPAT 1" $kernel_autoconf || grep -q "^#define CONFIG_COMPAT_MODULE 1" $kernel_autoconf; then
				compat_configured=yes
			fi
		fi
		AC_MSG_RESULT([$compat_configured])
		if test -z "$enable_kernel_module" -a "$xio_configured" = yes; then
			ENABLE_COMPAT_MODULE=n
		fi
	fi
fi

if test "$ENABLE_COMPAT_MODULE" = n; then
	AC_MSG_NOTICE([
NOTE:     Detected that COMPAT is already present in the kernel, so
NOTE:     building of kernel module is disabled.  To force building
NOTE:     of kernel module use the '--enable-kernel-module' option.])
fi

if test "$enable_kernel_module" = no; then
	ENABLE_COMPAT_MODULE=n
fi
if test "$bad_kernel_version" = yes; then
	ENABLE_COMPAT_MODULE=n
fi

AC_MSG_CHECKING([is ENABLE_COMPAT_MODULE defined])
if test "$ENABLE_COMPAT_MODULE" = y; then
		AC_MSG_RESULT([yes])
else
		AC_MSG_RESULT([no])
fi

AC_SUBST(ENABLE_COMPAT_MODULE)
AC_SUBST(KERNELMAKE_PARAMS)
AC_SUBST(KERNELCPPFLAGS)
AC_SUBST(KERNELCFLAGS)



AC_CONFIG_FILES([Makefile])
AC_OUTPUT

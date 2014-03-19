AC_INIT([xio-kernel],[2.0],[libxio@accellio.org])

AC_PROG_INSTALL

runver=`uname -r`
bad_kernel_version=no
ENABLE_XIO_MODULE=y
KERNELCFLAGS=

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


if test "$ENABLE_XIO_MODULE" = y; then
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
NOTE:    module from an earlier XIO release with the library from this
NOTE:    release.])
	else
		xio_configured=no
		kernel_autoconf=$kernelbuild/include/linux/autoconf.h
		AC_MSG_CHECKING([if XIO is configured in the kernel])
		if test -f $kernel_autoconf; then
			if grep -q "^#define CONFIG_XIO 1" $kernel_autoconf || grep -q "^#define CONFIG_XIO_MODULE 1" $kernel_autoconf; then
				xio_configured=yes
			fi
		fi
		AC_MSG_RESULT([$xio_configured])
		if test -z "$enable_kernel_module" -a "$xio_configured" = yes; then
			ENABLE_XIO_MODULE=n
		fi
	fi
fi

if test "$ENABLE_XIO_MODULE" = n; then
	AC_MSG_NOTICE([
NOTE:     Detected that XIO is already present in the kernel, so
NOTE:     building of kernel module is disabled.  To force building
NOTE:     of kernel module use the '--enable-kernel-module' option.])
fi

if test "$enable_kernel_module" = no; then
	ENABLE_XIO_MODULE=n
fi
if test "$bad_kernel_version" = yes; then
	ENABLE_XIO_MODULE=n
fi

AC_MSG_CHECKING([is ENABLE_XIO_MODULE defined])
if test "$ENABLE_XIO_MODULE" = y; then
		AC_MSG_RESULT([yes])
else
		AC_MSG_RESULT([no])
fi

AC_SUBST(ENABLE_XIO_MODULE)

if test "$ENABLE_XIO_MODULE" = y; then
	AC_MSG_CHECKING([if kernel defines kzalloc function])
	if egrep -qw "kzalloc" $kernelsrc/include/linux/slab.h; then
		AC_DEFINE(HAVE_KZALLOC, 1, [kzalloc() is defined])
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi

	isuml=no
	KERNELMAKE_PARAMS=
	KERNELCPPFLAGS=
	AC_MSG_CHECKING([if this is user mode linux])
	if test -f $kernelbuild/include/linux/autoconf.h && egrep -q "^#define CONFIG_(USERMODE|UML) 1" $kernelbuild/include/linux/autoconf.h; then
		isuml=yes
		KERNELMAKE_PARAMS="ARCH=um"
		KERNELCPPFLAGS="-D__arch_um__ -DSUBARCH=\\\"i386\\\" -D_LARGEFILE64_SOURCE -I${kernelsrc}/arch/um/include -Derrno=kernel_errno -I${kernelsrc}/arch/um/kernel/tt/include -I${kernelsrc}/arch/um/kernel/skas/include"
	fi
	AC_MSG_RESULT([$isuml])
	if test "$kernelbuild" != "$kernelsrc"; then
		KERNELMAKE_PARAMS="$KERNELMAKE_PARAMS O=$kernelbuild"
	fi
	AC_SUBST(KERNELMAKE_PARAMS)
	AC_SUBST(KERNELCPPFLAGS)
	AC_SUBST(KERNELCFLAGS)
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

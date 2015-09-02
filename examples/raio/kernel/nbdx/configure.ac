AC_INIT(nbdx, 0.1, libxio@accelio.org)

AC_PROG_INSTALL

runver=`uname -r`
pwd=`pwd`
kernelsrc=/lib/modules/${runver}/kernel
kernelbuild=/lib/modules/${runver}/build
kmoduledir=/lib/modules/${runver}/extra
xiodir=${pwd}/../../../..
KERNELMAKE_PARAMS=-I${xiodir}/include
XIOSYMS=${xiodir}/src/kernel/transport/rdma/Module.symvers
AC_SUBST(xiodir)
AC_SUBST(kernelsrc)
AC_SUBST(kernelbuild)
AC_SUBST(kmoduledir)
AC_SUBST(KERNELMAKE_PARAMS)
AC_SUBST(XIOSYMS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

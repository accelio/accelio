# this is example-file: Makefile.am

# the subdirectories of the project to go into
SUBDIRS = @subdirs@ @subdirs2@

#ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = autogen.sh

dox:
	doxygen

distclean-local:
	-@find . '(' -name '*.o' -o -name '*.a' -o -name '*.so' -o \
	      -name '*.cmd' -o -name '*.mod.c' -o -name '*.ko' -o \
	      -name '*.s' -o -name '*.order' -o -name '*.symvers' -o \
	      -name '*.unsigned' ')' -exec rm -f '{}' ';'

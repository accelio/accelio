#! /bin/bash

libtoolize  --force --copy --quiet  \
&& aclocal -I m4 \
&& automake --gnu --add-missing \
&& autoconf

subdirlist=("src/kernel/xio"				\
	    "src/kernel/transport/rdma"			\
	    "src/kernel/transport/tcp"			\
	    "examples/kernel/hello_world"		\
	    "examples/kernel/hello_world_mt"		\
	    "examples/raio/kernel/nbdx"			\
	    "tests/kernel/hello_test"                   \
	    "tests/kernel/hello_test_lat"               \
	    "tests/kernel/hello_test_ow"		\
	    "tests/kernel/direct_rdma_test")

for subdir in ${!subdirlist[*]} ; do
	#printf "	%s\n" "${subdirlist[$subdir]}"
	if [ -d "${subdirlist[$subdir]}" ]; then
		pushd "${subdirlist[$subdir]}"  > /dev/null
		./autogen.sh
		popd > /dev/null
	fi
done

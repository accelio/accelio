#! /bin/bash

libtoolize  --force --copy --quiet  \
&& aclocal -I m4 \
&& automake --gnu --add-missing \
&& autoconf 

subdirlist=("src/kernel/xio"				\
	    "src/kernel/rdma"				\
	    "examples/kernel/hello_world"		\
	    "examples/kernel/hello_world_mt")

for subdir in ${!subdirlist[*]} ; do
	#printf "	%s\n" "${subdirlist[$subdir]}"
	if [ -d "${subdirlist[$subdir]}" ]; then
		pushd "${subdirlist[$subdir]}"  > /dev/null
		./autogen.sh
		popd > /dev/null
	fi
done


#! /bin/bash

libtoolize  --force --copy --quiet  \
&& aclocal -I m4 \
&& automake --gnu --add-missing \
&& autoconf 

subdirlist="src/kernel/xio src/kernel/rdma src/examples/hello_world"
for subdir in $subdirlist ; do
	if [ -d $subdir ]; then
		pushd $subdir > /dev/null
		./autogen.sh
		popd > /dev/null
	fi
done


#! /bin/bash

libtoolize  --force --copy --quiet  \
&& aclocal -I m4 \
&& automake --gnu --add-missing \
&& autoconf 

subdirlist="src/kernel/hello"
for subdir in $subdirlist ; do
	if [ -d $subdir ]; then
		pushd $subdir > /dev/null
		./autogen.sh
		popd > /dev/null
	fi
done


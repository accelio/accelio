#!/bin/bash
#
# Author: Roi Dayan <roid@mellanox.com>
#

set -xe

base=${1:-/tmp/release}
codename=$(lsb_release -sc)
releasedir=$base/$(lsb_release -si)/WORKDIR
rm -fr $releasedir
mkdir -p $releasedir

vers=$(git describe --match "v*" | sed s/^v//)
name="libxio-$vers"
git archive --prefix "$name/" --format tar.gz -o $releasedir/${name}.orig.tar.gz HEAD
tar -C $releasedir -xzf $releasedir/${name}.orig.tar.gz
cd $releasedir/$name
dvers="$vers-1"
chvers=$(head -1 debian/changelog | perl -ne 's/.*\(//; s/\).*//; print')
if [ "$chvers" != "$dvers" ]; then
   DEBEMAIL="info@accelio.org" dch -D $codename --force-distribution -b -v "$dvers" "new version"
fi

: ${NPROC:=$(($(nproc) / 2))}
if test $NPROC -gt 1 ; then
    j=-j${NPROC}
fi
dpkg-buildpackage $j -uc -us
ls -ltr $releasedir/*.deb

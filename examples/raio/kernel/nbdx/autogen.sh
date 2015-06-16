#! /bin/bash

ln -sf ../../../../install-sh ./install-sh 
if [ -d backports ]; then
    git=`which git 2>/dev/null`
    if [ -n "$git" ]; then
        bport_branch=`git branch | grep -w backports`
        if [ -n "$bport_branch" ]; then
            git branch -D backports
        fi
        git checkout -b backports
        git am backports/*
    else
        patch -p1 < backports/*
    fi
fi
autoconf

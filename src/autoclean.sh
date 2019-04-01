#!/bin/sh

CUR_DIR=`pwd`
DIRS=( "${CUR_DIR}/config" "${CUR_DIR}" )

for DIR in ${DIRS[*]}; do
    echo "Cleaning ${DIR} ..."
    pushd ${DIR} >& /dev/null
    make distclean >& /dev/null
    rm -rf Makefile
    rm -rf Makefile.in
    rm -rf aclocal.m4
    rm -rf autom4te.cache
    rm -rf compile
    rm -rf config.guess
    rm -rf config.log
    rm -rf config.status
    rm -rf stamp-h1
    rm -rf config.h
    rm -rf config.h.in
    rm -rf config.sub
    rm -rf configure
    rm -rf depcomp
    rm -rf install-sh
    rm -rf libltdl
    rm -rf libtool
    rm -rf ltmain.sh
    rm -rf missing
    rm -rf *.loT
    rm -rf .deps
    rm -rf .libs
    rm -rf py-compile
    popd >& /dev/null
done

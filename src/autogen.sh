#! /bin/sh

SYSTEM=`uname -s`

if [[ ! -z ${SYSTEM} && ${SYSTEM} != "AIX" ]]; then
    echo "******************************"
    echo "Running libtoolize"
    echo "******************************"
    libtoolize --force --automake
fi

echo "******************************" && \
echo "Running aclocal"  && \
echo "******************************" && \
aclocal && \
echo "******************************" && \
echo "Running autoconf"  && \
echo "******************************" && \
autoconf && \
echo "******************************" && \
echo "Running autoheader"  && \
echo "******************************" && \
autoheader && \
echo "******************************" && \
echo "Running automake"  && \
echo "******************************" && \
automake --add-missing --copy && \
RETVAL=$? && \
echo "******************************" && \
echo "Retval: $RETVAL"  && \
echo "******************************"

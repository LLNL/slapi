AC_INIT([slapi], m4_esyscmd([cat ../VERSION ../DASH ../RELEASE | tr -d '\n']))
AC_CONFIG_HEADERS([config.h])
AC_PREREQ(2.59)
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])

##
# Checks for programs.
# Note that, once we move to automake 1.14 and beyond, the AM_PROG_CC_C_O macro
# will be obsolete and can be removed.
##
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_STDC

# Here lets assume we are using a GNU system
# This is so that we can have functions like
# strnlen,  etc. get properly defined on our
# system
AC_GNU_SOURCE

AC_PROG_MAKE_SET

AM_PATH_PYTHON([3.4])

##
# Epilogue.
##
AC_CONFIG_FILES(    \
  Makefile
)
AC_OUTPUT

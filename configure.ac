#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([question_authority], [0.1], [maker@tumbolandia.net])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/qa.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC([clang gcc cc])
AC_PROG_CC_C99
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h unistd.h])
AC_CHECK_HEADER(bsd/sys/queue.h, [:],
                [AC_MSG_ERROR([Could not find or include bsd queues. Please install libbsd-dev.])])
AC_CHECK_HEADERS([openssl/ssl.h openssl/bn.h openssl/x509.h openssl/rsa.h], [:],
                 AC_MSG_ERROR([Could not find or include openssl headers. Please install libssl-dev.]))

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
#AC_CHECK_FUNCS([dup2 setlocale strdup])

# Add compiler/linker flags
CFLAGS="$CFLAGS --std=c99 -I$(pwd)/src/include -Wall"

# Adding package options
AC_ARG_ENABLE(debug,
   AS_HELP_STRING([--enable-debug], [enable debugging, default: no]),
   CFLAGS+=" -DDEBUG -ggdb")

AC_OUTPUT([Makefile
           src/Makefile src/questions/Makefile
           src/apps/Makefile
           src/tests/Makefile src/questions/tests/Makefile
           ])

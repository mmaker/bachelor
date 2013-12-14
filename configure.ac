#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([question_authority], [0.1], [maker@tumbolandia.n])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/qa.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([openssl/ssl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
#AC_CHECK_FUNCS([dup2 setlocale strdup])

AC_OUTPUT([Makefile src/Makefile src/questions/Makefile src/apps/Makefile src/questions/tests/Makefile ])

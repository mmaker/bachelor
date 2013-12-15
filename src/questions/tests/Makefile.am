# unittesting my ass
AM_CFLAGS = -I ../../include/
AM_LDFLAGS = -lcrypto -lssl

check_PROGRAMS = test_qarith test_qstrings

test_qstrings_SOURCES = test_qstrings.c
test_qstrings_LDADD = ../libquestions.a
test_qarith_SOURCES = test_qarith.c
test_qarith_LDADD = ../libquestions.a

TESTS = $(check_PROGRAMS)

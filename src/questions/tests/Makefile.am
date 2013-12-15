# unittesting my ass
AM_CFLAGS = -I ../../include/ -ggdb -Wall
AM_LDFLAGS = -lcrypto -lssl
LDADD = ../libquestions.a

check_PROGRAMS = test_qarith test_qstrings test_wiener test_pollard
TESTS = $(check_PROGRAMS)

test_qstrings_SOURCES = test_qstrings.c
test_qarith_SOURCES = test_qarith.c
test_wiener_SOURCES = test_wiener.c
test_pollard_SOURCES = test_pollard.c

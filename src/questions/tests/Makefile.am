
# unittesting my ass
LDADD = ../libquestions.a -lssl -lcrypto

check_PROGRAMS = test_qarith test_qstrings test_wiener test_pollard test_dixon \
	         test_williams test_primes
TESTS = $(check_PROGRAMS) test_fermat.test test_metadata.test test_pollardrho.test


test_primes_sources = test_primes.c
test_williams_SOURCES = test_williams+1.c
test_qstrings_SOURCES = test_qstrings.c
test_qarith_SOURCES = test_qarith.c
test_wiener_SOURCES = test_wiener.c
test_pollard_SOURCES = test_pollard.c
test_dixon_SOURCES = test_dixon.c


SUBDIRS = tests/

# following the fucking manual, I am putting headers into the _SOURCES variable
#  <https://www.gnu.org/software/automake/manual/html_node/Headers.html>
EXAMPLE_QUESTION = example.c
WIENER_QUESTION = wiener.c    include/qwiener.h
POLLARD_QUESTION = pollard.c    include/qpollard.h
DIXON_QUESTION = dixon.c    include/qdixon.h
FERMAT_QUESTION = fermat.c
METADATA_QUESTION = metadata.c
POLLARDRHO_QUESTION = pollardrho.c
WILLIAMS_QUESTION = williams+1.c    include/qwilliams.h

QUESTIONS = $(WIENER_QUESTION) $(POLLARD_QUESTION) $(DIXON_QUESTION) \
	    $(FERMAT_QUESTION) $(EXAMPLE_QUESTION) $(METADATA_QUESTION) \
	    $(POLLARDRHO_QUESTION) $(WILLIAMS_QUESTION)

QLIBSOURCES =         qarith.c         include/qarith.h \
	            qstrings.c         include/qstrings.h \
                allquestions.c         include/questions.h \
	              primes.c         include/primes.h

lib_LIBRARIES = libquestions.a
libquestions_a_SOURCES = $(QUESTIONS) $(QLIBSOURCES)

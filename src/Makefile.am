SUBDIRS = questions/ apps/ tests/

AM_LDFLAGS = -lcrypto -lm -lssl

bin_PROGRAMS = qa
qa_SOURCES = qa.c qa_sock.c cmdline.c
qa_LDADD = questions/libquestions.a

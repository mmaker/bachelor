SUBDIRS = questions/ apps/ tests/

CC = clang

AM_LDFLAGS = -lcrypto -lm -lssl
AM_CFLAGS = --std=c99 -ggdb -I include/

bin_PROGRAMS = qa
qa_SOURCES = qa.c qa_sock.c cmdline.c
qa_LDADD = questions/libquestions.a

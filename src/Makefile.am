SUBDIRS = questions/
CC = clang
AM_CFLAGS = --std=c99 -ggdb -lm -lssl -lcrypto -I include/ -I questions/
bin_PROGRAMS = qa
qa_SOURCES = qa.c qa_sock.c cmdline.c
qa_LDADD = questions/libquestions.a

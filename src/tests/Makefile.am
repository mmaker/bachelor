# unittesting my ass
AM_CFLAGS = -I ../include/
AM_LDFLAGS = -lcrypto -lssl

check_PROGRAMS = test_qa_sock test_qa

test_qa_sock_SOURCES = test_qa_sock.c
test_qa_sock_LDADD = ../qa_sock.o

test_qa_SOURCES = test_qa
test_qa_LDADD = ../qa_sock.o ../cmdline.o ../qa.o ../questions/allquestions.o ../questions/libquestions.a

TESTS = $(check_PROGRAMS)

SUBDIRS = questions/ apps/ tests/

bin_PROGRAMS = qa
qa_SOURCES = qa.c qa_sock.c cmdline.c
qa_LDADD = questions/libquestions.a -lssl -lcrypto

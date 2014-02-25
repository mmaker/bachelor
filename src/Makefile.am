SUBDIRS = questions/ apps/ tests/

bin_PROGRAMS = qa indiana

qa_SOURCES = qa.c qa_sock.c cmdline.c
qa_LDADD = questions/libquestions.a -lssl -lcrypto

indiana_SOURCES = indiana.c qa_sock.c
indiana_LDADD = questions/libquestions.a -lssl -lcrypto

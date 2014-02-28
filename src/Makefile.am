SUBDIRS = questions/ apps/ tests/

bin_PROGRAMS = qa indiana stranamore

qa_SOURCES = qa.c qa_sock.c cmdline.c
qa_LDADD = questions/libquestions.a -lssl -lcrypto

indiana_SOURCES = indiana.c qa_sock.c
indiana_LDADD = questions/libquestions.a -lssl -lcrypto

stranamore_SOURCES = stranamore.c
stranamore_LDADD = -lssl -lcrypto

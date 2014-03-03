SUBDIRS = questions/ apps/ tests/

if CLUSTER
bin_PROGRAMS = qa indiana stranamore despicable

indiana_SOURCES = indiana.c qa_sock.c
indiana_LDADD = questions/libquestions.a -lssl -lcrypto

stranamore_SOURCES = stranamore.c
stranamore_LDADD = -lssl -lcrypto

despicable_SOURCES = despicable.c
despicable_LDADD = questions/libquestions.a -lssl -lcrypto

else
bin_PROGRAMS = qa

endif

qa_SOURCES = qa.c qa_sock.c cmdline.c
qa_LDADD = questions/libquestions.a -lssl -lcrypto

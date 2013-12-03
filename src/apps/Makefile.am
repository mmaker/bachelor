bin_PROGRAMS = gen

AM_CFLAGS = --std=c99

gen_SOURCES = gen.c
gen_LDFLAGS = -lcrypto -lssl


gen.o:
	$(CC) $(CFLAGS) $(LIBS) gen.c -c -o gen.o

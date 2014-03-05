#AUTOMAKE_OPTIONS = foereign
SUBDIRS = src/ book/
AUTOMAKE_ARGS = --add-missing

dist_doc_DATA = README


all-local:
	test -f primes.txt || ./src/apps/primes.sh

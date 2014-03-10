#AUTOMAKE_OPTIONS = foereign
SUBDIRS = src/ book/
AUTOMAKE_ARGS = --add-missing

dist_doc_DATA = README

if CLUSTER
all-local:
	test -f primes.txt || ./src/apps/primes.sh 20

else
all-local:
	test -f primes.txt || ./src/apps/primes.sh 1

endif

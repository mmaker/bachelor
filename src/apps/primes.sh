#!/bin/sh

> primes.txt

for i in {1..16}
do
    curl "http://primes.utm.edu/lists/small/millions/primes$i.zip" | funzip - | \
        tail -n +3 | sed -E 's/[[:space:]]+/\n/g' -| sed -e '/^$/d'  >> primes.txt
done

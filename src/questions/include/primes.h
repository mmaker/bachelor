#ifndef _QA_PRIMES_H_
#define _QA_PRIMES_H_


/* prime iterator object, now a file descriptor. */
typedef FILE pit_t;

pit_t *primes_init(void);

int primes_next(pit_t *, BIGNUM *p);

void prime_iterator_free(pit_t *it);

int smooth(BIGNUM *x, BN_CTX *ctx, char* v, size_t thresh);

#define primes_tell(it) ftell(it)
#define primes_seek(it, offset) fseek(it, offset, SEEK_SET)
#endif /* _QA_PRIMES_H_ */

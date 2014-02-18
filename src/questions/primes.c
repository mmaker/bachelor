/**
 * \file primes.c
 *
 * \brief Fast access to a prime pool
 *
 */

#include <openssl/bn.h>

static const char *PRIME_POOL_FILE = "primes.txt";
FILE *pool = NULL;
char sp[10];

/**
 * \brief Prime Poll initialization.
 *
 * \return 1 if the initialization suceeded
 *         0 if the initialization failed
 *         2 if the initialization had been already performed.
 */
int primes_init(void)
{
  if (pool) return 2;

  if (!(pool = fopen(PRIME_POOL_FILE, "r")))
    return 0;
  else
    return 1;
}


/**
 * \brief Next prime in the pool
 *
 * \return true if there was another prime, false otherwise.
 *
 */
int primes_next(BIGNUM* p)
{
  /* overlow on me, yeah */
  fscanf(pool, "%s", sp);
  BN_dec2bn(&p, sp);

  return 1;
}

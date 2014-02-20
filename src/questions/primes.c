/**
 * \file primes.c
 *
 * \brief Fast access to a prime pool
 *
 */
#include <strings.h>

#include <openssl/bn.h>

#include "qa/questions/primes.h"

static const char *PRIME_POOL_FILE = "primes.txt";

/**
 * \brief Prime Poll initialization.
 *
 * \return a new prime iterator if the initialization succeeded, NULL
 *         otherwise.
 */
pit_t *primes_init(void)
{
  return fopen(PRIME_POOL_FILE, "r");
}


/**
 * \brief Prime Pool Iterator destructor.
 *
 */
void prime_iterator_free(pit_t *it)
{
  /* XXX. check for errors. */
  fclose(it);
}

/**
 * \brief Next prime in the pool
 *
 * \return true if there was another prime, false otherwise.
 *
 */
int primes_next(pit_t *it, BIGNUM* p)
{
  static char sp[10];
  /* overlow on me, yeah */
  fscanf(it, "%s", sp);
  BN_dec2bn(&p, sp);

  return 1;
}

/**
 * \brief Test for smoothness
 *
 * Attempt to divide `x` for each prime pᵢ s.t. i <= thresh, filling a binary
 * vector with the powers mod 2.
 *
 * \return true if the prime is smooth w.r.t our prime pool, to the limits of
 *   thresh, false otherwise
 */
int
smooth(BIGNUM *x, BN_CTX *ctx, char* v, size_t thresh)
{
  BIGNUM *p = BN_new();
  BIGNUM *rem = BN_new();
  BIGNUM *dv = BN_new();
  pit_t *it;
  size_t i;

  i = 0;
  BN_zero(rem);
  bzero(v, thresh);
  if (BN_cmp(x, BN_value_one()) < 1) return 0;

  i = 0;
  for (it = primes_init();
       primes_next(it, p) && i < thresh;
       i++) {
    BN_div(dv, rem, x, p, ctx);
    for (v[i] = 0; BN_is_zero(rem); BN_div(dv, rem, x, p, ctx)) {
      v[i] = (v[i] + 1) % 2;
      BN_copy(x, dv);

      if (!BN_cmp(x, BN_value_one())) {
        BN_free(p);
        return 1;
      }
    }
  }

  prime_iterator_free(it);
  BN_free(p);
  return 0;
}

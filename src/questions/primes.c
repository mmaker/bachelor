/**
 * \file primes.c
 *
 * \brief Fast access to a prime pool
 *
 */
#include <stdint.h>

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
smooth(BIGNUM *x, BN_CTX *ctx, uint8_t* v, size_t thresh)
{
  BIGNUM *p = BN_new();
  BIGNUM *rem = BN_new();
  BIGNUM *dv = BN_new();
  size_t i;

  i = 0;
  BN_zero(rem);
  if (BN_cmp(x, BN_value_one()) < 1) return 0;

  i = 0;
  for (primes_init(); primes_next(p) && i < thresh; i++) {
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

  BN_free(p);
  return 0;
}

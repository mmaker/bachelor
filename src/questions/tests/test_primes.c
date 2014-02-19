#include <assert.h>
#include <stdint.h>

#include <openssl/bn.h>

#include "qa/questions/primes.h"

void test_primes(void)
{
  BIGNUM *p = BN_new();
  BIGNUM *check = BN_new();

  assert(primes_init());

  BN_dec2bn(&check, "2");
  primes_next(p);
  assert(!BN_cmp(check, p));

  BN_dec2bn(&check, "3");
  primes_next(p);
  assert(!BN_cmp(check, p));

  BN_dec2bn(&check, "5");
  primes_next(p);
  assert(!BN_cmp(check, p));

  BN_free(p);
  BN_free(check);
}

void
test_smooth(void)
{
  BIGNUM *x = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  static const int primes = 100;
  uint8_t v[primes];


  BN_one(x);
  assert(!smooth(x, ctx, v, primes));

  BN_dec2bn(&x, "2");
  assert(smooth(x, ctx, v, primes));

  BN_dec2bn(&x, "1573");
  assert(smooth(x, ctx, v, primes));

  BN_CTX_free(ctx);
  BN_free(x);
}


int main(int argc, char **argv)
{
  test_primes();

  /* XXX. shit we DO NEED an iterator object asap. */
  extern FILE *pool;
  fclose(pool);
  pool = NULL;

  test_smooth();

  return 0;
}

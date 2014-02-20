#include <assert.h>
#include <stdint.h>

#include <openssl/bn.h>

#include "qa/questions/primes.h"

void test_primes(void)
{
  BIGNUM *p = BN_new();
  BIGNUM *check = BN_new();
  pit_t *it;

  assert((it = primes_init()));

  BN_dec2bn(&check, "2");
  primes_next(it, p);
  assert(!BN_cmp(check, p));

  BN_dec2bn(&check, "3");
  primes_next(it, p);
  assert(!BN_cmp(check, p));

  BN_dec2bn(&check, "5");
  primes_next(it, p);
  assert(!BN_cmp(check, p));

  prime_iterator_free(it);
  BN_free(p);
  BN_free(check);
}

void
test_smooth(void)
{
  BIGNUM *x = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  static const int primes = 100;
  char v[primes];

  BN_one(x);
  assert(!smooth(x, ctx, v, primes));

  BN_dec2bn(&x, "2");
  assert(smooth(x, ctx, v, primes));

  BN_dec2bn(&x, "1573");
  assert(smooth(x, ctx, v, primes));

  BN_CTX_free(ctx);
  BN_free(x);
}

void
test_iterator(void)
{
  BIGNUM *p1 = BN_new();
  BIGNUM *p2 = BN_new();
  pit_t *it1, *it2;

  it1 = primes_init();
  it2 = primes_init();
  assert(it1 && it2);
  primes_next(it1, p1);
  primes_next(it2, p2);
  assert(!BN_cmp(p1, p2));

  primes_next(it1, p1);
  primes_next(it1, p1);
  primes_next(it2, p2);
  assert(BN_cmp(p1, p2) > 0);

  prime_iterator_free(it1);
  prime_iterator_free(it2);
}


int main(int argc, char **argv)
{
  test_primes();
  test_smooth();
  test_iterator();

  return 0;
}

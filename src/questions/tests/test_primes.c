#include <assert.h>

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

int main(int argc, char **argv)
{
  test_primes();
  return 0;
}

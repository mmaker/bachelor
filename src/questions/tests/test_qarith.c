#include <assert.h>

#include <openssl/bn.h>
#include "qa/questions/qarith.h"

static void test_BN_sqrtmod(void)
{
  BIGNUM *a, *b, *expected;
  BIGNUM *root, *rem;
  BIGNUM *mayzero;
  BN_CTX *ctx;

  a = b = expected = NULL;
  root = BN_new();
  rem = BN_new();
  mayzero = BN_new();
  ctx = BN_CTX_new();

  BN_dec2bn(&a, "144");
  BN_dec2bn(&expected, "12");
  BN_sqrtmod(root, rem, a, ctx);
  assert(!BN_cmp(expected, root));
  assert(BN_is_zero(rem));

  BN_dec2bn(&a, "15245419238964964");
  BN_dec2bn(&expected, "123472342");
  BN_sqrtmod(root, rem, a, ctx);
  assert(!BN_cmp(root, expected));
  assert(BN_is_zero(rem));

  BN_dec2bn(&a, "5");
  BN_dec2bn(&expected, "2");
  BN_sqrtmod(root, rem, a, ctx);
  assert(!BN_cmp(root, expected));
  assert(BN_is_one(rem));

  BN_dec2bn(&a, "106929");
  BN_dec2bn(&expected, "327");
  BN_sqrtmod(root, rem, a, ctx);
  assert(BN_is_zero(rem));
  assert(!BN_cmp(root, expected));

  BN_free(root);
  BN_free(rem);
  BN_free(mayzero);
  BN_CTX_free(ctx);
  BN_free(a);
  BN_free(expected);
}


int main(int argc, char **argv)
{
  test_BN_sqrtmod();
  return 0;

}

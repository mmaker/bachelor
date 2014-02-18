#include <assert.h>

#include <openssl/bn.h>

#include "qa/questions/questions.h"
#include "qa/questions/qarith.h"
#include "qa/questions/qwilliams.h"

void test_lucas(void)
{
  BIGNUM *two = BN_new();
  BIGNUM *v = BN_new();
  BIGNUM *w = BN_new();
  BIGNUM *h = BN_new();
  BIGNUM *tau = BN_new();
  BIGNUM
    *vcheck = BN_new(),
    *wcheck = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_one(two); BN_uiadd1(two);
  BN_copy(w, two);
  BN_dec2bn(&tau, "5");
  BN_copy(v, tau);

  /* <V₁, V₀> */
  assert(!BN_cmp(v, tau));
  assert(!BN_cmp(w, two));
  /* <V₃, V₂> */
  BN_dec2bn(&h, "3");
  BN_dec2bn(&vcheck, "110");
  BN_dec2bn(&wcheck, "23");

  lucas(v, w, h, tau, ctx);
  assert(!BN_cmp(wcheck, w));
  BN_print_fp(stderr, v);
  assert(!BN_cmp(vcheck, v));

  /* <V₆, V₅> */
  BN_dec2bn(&h, "2");
  BN_dec2bn(&vcheck, "12098");
  BN_dec2bn(&wcheck, "2525");

  lucas(v, w, h, tau, ctx);
  assert(!BN_cmp(wcheck, w));
  assert(!BN_cmp(vcheck, v));

  BN_free(tau);
  BN_free(v);
  BN_free(w);
  BN_free(h);
  BN_free(vcheck);
  BN_free(wcheck);
  BN_CTX_free(ctx);

}


int main(int argc, char **argv)
{
  test_lucas();
}

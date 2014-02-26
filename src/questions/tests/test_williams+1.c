#include <assert.h>

#include <openssl/bn.h>

#include "qa/questions/questions.h"
#include "qa/questions/qarith.h"
#include "qa/questions/qwilliams.h"

void test_lucas(void)
{
  BIGNUM *v = BN_new();
  BIGNUM *w = BN_new();
  BIGNUM *h = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *tau = BN_new();
  BIGNUM
    *vcheck = BN_new(),
    *wcheck = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_copy(w, BN_value_two());
  BN_dec2bn(&tau, "5");
  BN_copy(v, tau);
  BN_dec2bn(&n, "100000000000");

  /* <V₁, V₀> */
  assert(!BN_cmp(v, tau));
  assert(!BN_cmp(w, BN_value_two()));
  /* <V₃, V₂> */
  BN_dec2bn(&h, "3");
  BN_dec2bn(&vcheck, "110");
  BN_dec2bn(&wcheck, "23");

  lucas(v, w, h, tau, n, ctx);
  assert(!BN_cmp(wcheck, w));
  BN_print_fp(stderr, v);
  assert(!BN_cmp(vcheck, v));

  /* <V₆, V₅> */
  BN_dec2bn(&h, "2");
  BN_dec2bn(&vcheck, "12098");
  BN_dec2bn(&wcheck, "2525");

  lucas(v, w, h, tau, n, ctx);
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

void test_lehmer_thm(void)
{
  BIGNUM
    *v = BN_new(),
    *w = BN_new(),
    *h = BN_new(),
    *n = BN_new(),
    *tau = BN_new(),
    *p = BN_new(),
    *q = BN_new(),
    *g = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_copy(w, BN_value_two());
  BN_dec2bn(&tau, "2");
  BN_copy(v, tau);
  BN_dec2bn(&p,
            "181857351165158586099319592412492032999818333818932850952491024"
            "131283899677766672100915923041329384157985577418702469610834914"
            "6296393743554494871840505599");
  BN_dec2bn(&q,
            "220481921324130321200060036818685031159071785249502660004347524"
            "831733577485433929892260897846567483448177204481081755191897197"
            "38283711758138566145322943999");
  BN_mul(n, p, q, ctx);
  /* p + 1 */
  BN_dec2bn(&h,
            "181857351165158586099319592412492032999818333818932850952491024"
            "131283899677766672100915923041329384157985577418702469610834914"
            "6296393743554494871840505600");
  lucas(v, w, h, tau, n, ctx);
  BN_sub(v, v, BN_value_two());
  BN_gcd(g, v, n, ctx);
  assert(!BN_is_one(g) && !BN_cmp(g, n));


  BN_free(q);
  BN_free(p);
  BN_free(tau);
  BN_free(v);
  BN_free(w);
  BN_free(h);

  BN_CTX_free(ctx);
}


int main(int argc, char **argv)
{
  test_lucas();
  test_lehmer_thm();
}

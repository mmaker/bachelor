#include <assert.h>

#include <openssl/bn.h>

#include "qa/questions/questions.h"
#include "qa/questions/qarith.h"
#include "qa/questions/qwilliams.h"

void test_lucas(void)
{
  BIGNUM
    *v = BN_new(),
    *h = BN_new(),
    *n = BN_new(),
    *vcheck = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_dec2bn(&v, "5");
  BN_dec2bn(&n, "100000000000");

  /* <V₃, V₂> */
  BN_dec2bn(&h, "3");
  BN_dec2bn(&vcheck, "110");
  lucas(v, h, n, ctx);
  assert(!BN_cmp(vcheck, v));
  /* <V₆, V₅> */
  BN_dec2bn(&h, "2");
  BN_dec2bn(&vcheck, "12098");
  lucas(v, h, n, ctx);
  assert(!BN_cmp(vcheck, v));


  /* another sequence */
  BN_dec2bn(&v, "5");
  BN_dec2bn(&n, "100");

  BN_dec2bn(&h, "11");
  BN_dec2bn(&vcheck, "45");
  lucas(v, h, n, ctx);
  assert(!BN_cmp(v, vcheck));

  BN_dec2bn(&h, "9");
  BN_dec2bn(&vcheck, "30");
  lucas(v, h, n, ctx);
  assert(!BN_cmp(v, vcheck));

  BN_dec2bn(&h, "3");
  BN_dec2bn(&vcheck, "10");
  lucas(v, h, n, ctx);
  assert(!BN_cmp(v, vcheck));


  BN_free(v);
  BN_free(h);
  BN_free(vcheck);
  BN_CTX_free(ctx);
}

void test_lehmer_thm(void)
{
  BIGNUM
    *v = BN_new(),
    *v2 = BN_new(),
    *h = BN_new(),
    *n = BN_new(),
    *p = BN_new(),
    *q = BN_new(),
    *g = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  BN_dec2bn(&v, "2");
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
  lucas(v, h, n, ctx);
  BN_sub(v2, v, BN_value_two());
  BN_gcd(g, v2, n, ctx);
  assert(!BN_is_one(g));

  /* another test */
  BN_dec2bn(&v, "3");
  BN_dec2bn(&p,
            "181857351165158586099319592412492032999818333818932850952491024"
            "131283899677766672100915923041329384157985577418702469610834914"
            "62963937435544948718405055999");
  BN_generate_prime(q, 512, 1, NULL, NULL, NULL, NULL);
  BN_mul(n, p, q, ctx);

  BN_sub(h, p, BN_value_one());
  BN_mul(h, h, BN_value_two(), ctx);
  lucas(v, h, n, ctx);

  BN_mod_sub(v2, v, BN_value_two(), n, ctx);
  BN_gcd(g, v2, n, ctx);
  assert(!BN_is_one(g));
  assert(BN_cmp(g, n));

  BN_free(q);
  BN_free(p);
  BN_free(v);
  BN_free(v2);
  BN_free(h);

  BN_CTX_free(ctx);
}


int main(int argc, char **argv)
{
  test_lucas();
  test_lehmer_thm();
}

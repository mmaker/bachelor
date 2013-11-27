#include <assert.h>
#include <math.h>

#include "questions.h"
#include "qwiener.h"


/**
 * \brief Testing the continued fractions generator.
 */
void test_cf(void)
{
  bigfraction_t x = {NULL, NULL};
  cf_t* f;
  size_t i;
  bigfraction_t *it;
  BIGNUM* expected;

  f = cf_new();
  x.h = BN_new();
  x.k = BN_new();
  expected = BN_new();

   /*
   *  Testing aᵢ
   *
   *              1
   * √2 = 1 + ⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽
   *                  1
   *           2 +  ⎽⎽⎽⎽⎽⎽
   *                 2 + …
   *
   */
  BN_dec2bn(&x.h, "14142135623730951");
  BN_dec2bn(&x.k, "10000000000000000");
  BN_dec2bn(&expected, "2");
  cf_init(f, x.h, x.k);

  it = cf_next(f);
  assert(BN_is_one(f->a));
  for (i=0; i!=5 && it; i++) {
    it = cf_next(f);
    assert(!BN_cmp(f->a, expected));
  }
  assert(i==5);

  /*
   * Testing hᵢ/kᵢ
   *
   *                        1
   * φ = (1+√5)/2  = 1 + ⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽
   *                            1
   *                      1 + ⎽⎽⎽⎽⎽
   *                          1 + …
   */
  const char* fib[] = {"1", "1", "2", "3", "5", "8", "13"};
  BN_dec2bn(&x.h, "323606797749979");
  BN_dec2bn(&x.k, "200000000000000");
  cf_init(f, x.h, x.k);
  it = cf_next(f);
  for (i=1; i!=7; i++) {
    BN_dec2bn(&expected, fib[i]);
    assert(!BN_cmp(it->h, expected));

    BN_dec2bn(&expected, fib[i-1]);
    assert(!BN_cmp(it->k, expected));

    it=cf_next(f);
  }
}


int main(int argc, char ** argv)
{
  test_cf();
  return 0;
}

#include <assert.h>
#include <math.h>

#include "questions.h"
#include "qwiener.h"

/**
 * \brief Testing the continued fractions generator.
 */
void test_cf(void)
{
  double x;
  struct cf f;
  struct fraction *it;
  size_t i;

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
  x = sqrt(2);
  cfrac_init(&f, x);

  it = cfrac_next(&f);
  assert(it && f.a == 1);
  it = cfrac_next(&f);
  for (i=0; i!=10 && it; i++) {
    assert(f.a == 2);
    it = cfrac_next(&f);
  }
  assert(i==10);

  /*
   * Testing hᵢ/kᵢ
   *
   *                        1
   * φ = (1+√5)/2  = 1 + ⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽
   *                            1
   *                      1 + ⎽⎽⎽⎽⎽
   *                          1 + …
   */
  int fib[] = {1, 1, 2, 3, 5, 8, 13};
  x = (1 + sqrt(5))/2;
  cfrac_init(&f, x);
  it = cfrac_next(&f);
  for (i=1; i!=7; i++) {
    assert(it->h == fib[i] &&
           it->k == fib[i-1]);
    it=cfrac_next(&f);
  }

}


int main(int argc, char ** argv)
{
  test_cf();
  return 0;
}

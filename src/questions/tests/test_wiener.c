#include <assert.h>
#include <error.h>
#include <errno.h>
#include <libgen.h>
#include <math.h>
#include <string.h>


#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "qa/questions/questions.h"
#include "qa/questions/qwiener.h"

/**
 * \brief Testing the continued fractions generator.
 *
 *
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

  BN_dec2bn(&x.h, "60728973");
  BN_dec2bn(&x.k, "160523347");
  cf_init(f, x.h, x.k);
  /* 0 */
  it = cf_next(f);
  /* 1 / 2 */
  it = cf_next(f);
  BN_dec2bn(&expected, "2");
  assert(BN_is_one(it->h) && !BN_cmp(it->k, expected));
  /* 1 / 3 */
  it = cf_next(f);
  BN_dec2bn(&expected, "3");
  assert(BN_is_one(it->h) && !BN_cmp(it->k, expected));
  /* 2 / 5 */
  it = cf_next(f);
  BN_dec2bn(&expected, "2");
  assert(!BN_cmp(expected, it->h));
  BN_dec2bn(&expected, "5");
  assert(!BN_cmp(expected, it->k));
  /* 3 / 8 */
  it = cf_next(f);
  BN_dec2bn(&expected, "3");
  assert(!BN_cmp(expected, it->h));
  BN_dec2bn(&expected, "8");
  assert(!BN_cmp(expected, it->k));
  /* 14/ 37 */
  it = cf_next(f);
  BN_dec2bn(&expected, "14");
  assert(!BN_cmp(expected, it->h));
  BN_dec2bn(&expected, "37");
  assert(!BN_cmp(expected, it->k));
}


void test_wiener(void)
{
  X509 *crt;
  RSA *rsa;
  FILE *fp = fopen("wiener_test.crt", "r");

  if (!fp) exit(EXIT_FAILURE);
  crt = PEM_read_X509(fp, NULL, 0, NULL);
  if (!crt) {
    exit(EXIT_FAILURE);
  }

  rsa = X509_get_pubkey(crt)->pkey.rsa;
  /* assert(WienerQuestion.test(crt)); */
  assert(WienerQuestion.ask_rsa(rsa));
}

int main(int argc, char ** argv)
{
  if (WienerQuestion.setup) WienerQuestion.setup();

  test_cf();
  test_wiener();

  if (WienerQuestion.teardown) WienerQuestion.teardown();
  return 0;
}

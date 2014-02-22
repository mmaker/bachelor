#include <assert.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "qa/questions/qarith.h"


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

void
test_qa_RSA_recover(void)
{
  BIGNUM *p  = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *d = BN_new();
  RSA *rsa = RSA_new();
  BN_CTX *ctx = BN_CTX_new();
  RSA *priv;

  BN_dec2bn(&rsa->e, "65537");
  BN_hex2bn(&p,
            "00F131E99152802D41ED511C66832331190F1C2485778150DC4668AD560F6D"
            "6C46BD771CE03006BDFD98F280C36BA3A3E2A25F0563AC4841A75550809409"
            "262BF4B42386E09227D23074EDAC310C57F73262D023CECD95782719EDF927"
            "816E8F2E925E39EE3FD0307B40F155F88EAE1C75CB36F1C8B594F548A74F30"
            "ED6F3084A3");
  BN_hex2bn(&d,
            "7B6E2D23FB6D344A4CAAFA0CFFE1D31B377487A3A5F9956A457C4CEBB3AD8C"
            "E297332AB7C7432DC9512F12343F05FB92A0A1F7C7BCC8E1D3AE6FFDE3666E"
            "32ED04B43C75058CA314F46872A3E5F92D31081271609207DABCE6FB2D81B8"
            "D88AE3324F1AF406471580A964AA38396EF08C41B927F71A4E39EAB19EB84B"
            "C260A981AF01DA72998485C91749B0E7FD6FE10CAD8D534B459B5122297DEE"
            "37EB4B7644DCC186DF7ACD3FC91BB9BA374EFBEA450F6BE10E87FD00ADA7FC"
            "7C9E40B1786093CCC2F7E952DE3E31F8B96D839A76941CB8AD01B93A35AA8E"
            "18357E63644EC57792938E001BF6092B5C034A7C11BBE3E0A722A9932F2D6E"
            "B828B16F6067D001");
  BN_hex2bn(&rsa->n,
            "D10EA00ADAA09BC39D892437450CD7736311060C57CA16B487CDD70F648EF6"
            "685FF19DC22AA734F1D25A21EC2234D01E09BE223AB374F2DD4486C897EEA6"
            "70FF0EDE2C63771602501A7265D6016FA8D78EDCDA22FB476B177F8B45323B"
            "2981D15348CC37A2B55489A89FDDE4CAEBBA793F31389857940DFAA6B4D76F"
            "0C30820395DDB8DDD896756BCAB9A6452D2074ADD36FE1D7F7793A0D1488F3"
            "B4699C055CEA95539F4A93DF0BBACEC803C4E8BAF8CCDF8731C0F7A4827ABA"
            "93325E51126330A96A15F9504FA440AF35D3FD13AC1F7E760F29B16EA84B7D"
            "C36FE26CCF8F2371C0A3FB745CFEFFA5CDA43C1C2C25DDAE6F1FE83A3FFB08"
            "04589D2B5C8E38A3");
  BN_hex2bn(&q,
            "00DDE3B497FC7AD2CC4B4B8F23638E5CF83DC5472804E4B83589C16DFC7A6B"
            "595F4D88AE6241B9FB5770E06837FDC9EE71D025C2373DF578C6F31E542017"
            "2A050CD89BE9ED0FC166F6CE069CDFD068549EA58F70A0178BDE0F0FC0A3A9"
            "8373315A69B2D15D094B774C22AA8928056645B4EBBBF2FF6B194B48514DCB"
            "9E2D92BC01");

  priv = qa_RSA_recover(rsa, p, ctx);
  assert(!BN_cmp(priv->d, d));
  assert(!BN_cmp(priv->q, q));

  BN_free(p);
  BN_free(q);
  BN_free(d);
  RSA_free(rsa);
  RSA_free(priv);
  BN_CTX_free(ctx);
}


void
test_BN_min(void)
{
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();

  BN_dec2bn(&a, "10");
  BN_dec2bn(&b, "11");
  assert(!BN_cmp(BN_min(a, b), a));

  BN_dec2bn(&a, "-100");
  BN_dec2bn(&b, "-101");
  assert(!BN_cmp(BN_min(a, b), b));

  BN_free(a);
  BN_free(b);
}

void
test_BN_abs(void)
{
  BIGNUM *a = BN_new();
  BIGNUM *check = BN_new();

  BN_dec2bn(&a, "-100");
  BN_dec2bn(&check, "100");
  BN_abs(a);
  assert(!BN_cmp(a, check));

  BN_abs(a);
  assert(!BN_cmp(a, check));

  BN_free(check);
  BN_free(a);
}


void test_BN_value_two(void)
{
  BIGNUM *two = BN_new();

  BN_dec2bn(&two, "2");
  assert(!BN_cmp(two, BN_value_two()));

  BN_free(two);
}


int main(int argc, char **argv)
{
  test_cf();
  test_BN_sqrtmod();
  test_qa_RSA_recover();
  test_BN_min();
  test_BN_abs();
  test_BN_value_two();

  return 0;

}

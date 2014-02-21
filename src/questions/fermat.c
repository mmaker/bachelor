/**
 * \file Fermat's factorization
 *
 * According to the Digital Signature Standard,  |p - q| = Δ > √N 2⁻¹⁰⁰
 * Otherwise, it is possible to factorize N using Fermat's Factorization.
 * Specifically, we try to solve
 *  a² - N = b²
 * which can be algebreically factorable as
 *  N = (a-b)(a+b), where p = (a-b) q = (a+b)
 *                  and by construction a ~ ⌈√N⌉
 */
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "qa/questions/questions.h"
#include "qa/questions/qarith.h"


static RSA *
fermat_question_ask(const RSA *rsa)
{
  BIGNUM
    *a = BN_new(),
    *b = BN_new(),
    *a2 = BN_new(),
    *b2 = BN_new();
  BIGNUM *n = rsa->n;
  BIGNUM
    *tmp = BN_new(),
    *rem = BN_new(),
    *dssdelta = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  RSA *ret = NULL;

  BN_sqrtmod(tmp, rem, n, ctx);
  /* Δ = |p - q| = |a + b - a + b| = |2b| > √N  2⁻¹⁰⁰ */
  BN_rshift(dssdelta, tmp, 101);
  BN_copy(a, tmp);
  BN_sqr(a2, a, ctx);

  do {
    /* a² += 2a + 1 */
    BN_lshift1(tmp, a);
    BN_uiadd1(tmp);
    BN_uadd(a2, a2, tmp);
    /* a += 1 */
    BN_uiadd1(a);
    /* b² = a² - N */
    BN_usub(b2, a2, n);
    /* b */
    BN_sqrtmod(b, rem, b2, ctx);
  } while (!BN_is_zero(rem) && BN_ucmp(b, dssdelta) < 1);

  if (BN_is_zero(rem)) {
    BN_sqrtmod(a, rem, a2, ctx);
    assert(BN_is_zero(rem));
    BN_uadd(a, a, b);
    ret = qa_RSA_recover(rsa, a, ctx);
  }

  BN_CTX_free(ctx);
  BN_free(a);
  BN_free(b);
  BN_free(a2);
  BN_free(b2);
  BN_free(dssdelta);
  BN_free(tmp);
  BN_free(rem);
  return ret;
}


qa_question_t FermatQuestion = {
  .name = "fermat",
  .pretty_name = "Fermat's Factorization",
  .ask_rsa = fermat_question_ask,
  .ask_crt = NULL,
  .test = NULL,
  .setup = NULL,
  .teardown = NULL,
};

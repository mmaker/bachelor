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
  BN_CTX *ctx;
  BIGNUM *a, *b, *a2, *b2;
  BIGNUM *n;
  BIGNUM *tmp, *rem, *dssdelta;
  RSA *ret = NULL;

  ctx = BN_CTX_new();
  n = rsa->n;
  a = BN_new();
  b = BN_new();
  a2 = BN_new();
  b2 = BN_new();
  rem = BN_new();
  tmp = BN_new();
  dssdelta = BN_new();

  BN_sqrtmod(tmp, rem, n, ctx);
  /* Δ = |p - q| = |a + b - a + b| = |2b| > √N  2⁻¹⁰⁰ */
  BN_rshift(dssdelta, tmp, 101);
  /* a² = (⌊√N⌋ + 1)² =  N + 1 + 2⌊√N⌋ */
  BN_copy(a, tmp);
  BN_uiadd1(a);
  /* b² = a² - N */
  BN_sub(b2, a2, n);

  do {
    /* b² += 2a + 1 */
    BN_lshift(tmp, a, 1);
    BN_uiadd1(tmp);
    BN_uadd(b2, b2, tmp);
    /* a += 1 */
    BN_uiadd1(a);
    /* b */
    BN_sqrtmod(b, rem, b2, ctx);
  } while (!BN_is_zero(rem) && BN_ucmp(b, dssdelta) == 1);

  if (BN_is_zero(rem)) {
    /* p, q found :) */
    ret = RSA_new();
    ret->q = BN_new();
    ret->p = BN_new();

    BN_sqrtmod(a, rem, a2, ctx);
    assert(BN_is_zero(rem));
    BN_uadd(ret->p, a, b);
    BN_usub(ret->q, a, b);
  }

  BN_CTX_free(ctx);
  BN_free(a);
  BN_free(b);
  BN_free(a2);
  BN_free(b2);
  BN_free(dssdelta);
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

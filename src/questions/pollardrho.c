/**
 * \file pollardrho.c
 *
 * \brief Pollard's ρ factorization method.
 *
 * This file contains two implementations of the pollard's ρ algorithm, used in
 * order to attempt a factorization of N.
 */

#include <openssl/rsa.h>

#include <qa/questions/qarith.h>
#include <qa/questions/questions.h>


static RSA*
pollardrho_question_ask_rsa(const RSA *rsa)
{
  RSA *ret = NULL;
  BIGNUM
    *x = NULL,
    *y = NULL;
  BIGNUM *n;
  BIGNUM* two;
  BIGNUM *tmp;
  BIGNUM *gcd;
  BN_CTX *ctx;

  ctx = BN_CTX_new();
  gcd = BN_new();
  x = BN_new();
  y = BN_new();
  tmp = BN_new();
  n = rsa->n;
  two = BN_new();

  /* initialization */
  BN_one(gcd);
  BN_pseudo_rand(x, 512, 0, 0);
  BN_copy(y, x);
  BN_one(two); BN_uiadd1(two);


  while (!BN_cmp(gcd, BN_value_one())) {
    /* x ← x² + 1 (mod N) */
    BN_mod_sqr(x, x, n, ctx);
    BN_uiadd1(x);
    /* y ← y⁴ + 2y² + 2 (mod N) */
    BN_mod_sqr(tmp, y, n, ctx);
    BN_mod_sqr(y, tmp, n, ctx);
    BN_lshift1(tmp, tmp);
    BN_mod_add(y, y, tmp, n, ctx);
    BN_mod_add(y, y, two, n, ctx);
    /* gcd(|x-y|, N) */
    BN_mod_sub(tmp, x, y, n, ctx);
    BN_gcd(gcd, tmp, n, ctx);
  }

  if (BN_ucmp(gcd, n) != 0)
    ret = qa_RSA_recover(rsa, gcd, ctx);

  BN_free(tmp);
  BN_free(x);
  BN_free(y);
  BN_free(gcd);
  BN_free(two);
  return ret;
}

qa_question_t PollardRhoQuestion = {
  .name = "pollardrho",
  .pretty_name = "Pollard's rho factorization",
  .ask_rsa = pollardrho_question_ask_rsa
};

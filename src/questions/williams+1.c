/**
 * \file williams+1.c
 * \brief An implementation of William's p+1 Attack.
 *
 * William's attack, published in 1982, describes a factorization algorithm
 * based on lucas sequences and Lehmer's theorem.
 *
 */
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "qa/questions/qarith.h"
#include "qa/questions/questions.h"

/**
 * \brief Lucas Sequence Multiplier.
 *
 * Given a pair <Vᵢ, Vᵢ₋₁>, terms of a lucas sequence with parameter τ,
 * compute <Vₕᵢ, Vₕᵢ₋₁>
 */
void lucas(BIGNUM *v, BIGNUM *w,
           BIGNUM *h, BIGNUM *tau,
           BN_CTX *ctx)
{
  BIGNUM *vv;
  BIGNUM *vw;
  BIGNUM *u;

  vv = BN_new();
  vw = BN_new();
  u = BN_new();

  for (;
       BN_ucmp(h, BN_value_one()) > 0;
       BN_rshift1(h, h)) {
    if (BN_is_odd(h)) {
      BN_sqr(vv, v, ctx);
      /* v = τv² - vw - τ */
      BN_mul(u, tau, vv, ctx);
      BN_mul(vw, v, w, ctx);
      BN_sub(u, u, vw);
      BN_sub(u, u, tau);
      /* w = w² - 2 */
      BN_sub(w, vv, BN_value_one());
      BN_sub(w, w, BN_value_one());
    } else {
      BN_sqr(vv, v, ctx);
      /* v = v² - 2 */
      BN_sub(u, vv, BN_value_one());
      BN_sub(u, u, BN_value_one());
      /* w = vw - τ */
      BN_mul(vw, v, w, ctx);
      BN_sub(w, vw, tau);
    }
    BN_copy(v, u);
  }

  BN_free(u);
  BN_free(vv);
  BN_free(vw);
}

static RSA*
williams_question_ask_rsa(const RSA* rsa)
{
  RSA *ret = NULL;
  return ret;
}

qa_question_t WilliamsQuestion = {
  .name = "p+1",
  .pretty_name = "William's p+1 factorization",
  .ask_rsa = williams_question_ask_rsa
};

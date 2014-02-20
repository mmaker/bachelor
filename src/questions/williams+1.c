/**
 * \file williams+1.c
 * \brief An implementation of William's p+1 Attack.
 *
 * William's attack, published in 1982, describes a factorization algorithm
 * based on lucas sequences and Lehmer's theorem.
 *
 */
#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "qa/questions/primes.h"
#include "qa/questions/qarith.h"
#include "qa/questions/questions.h"

/**
 * \brief Lucas Sequence Multiplier.
 *
 * Given a pair <Vᵢ, Vᵢ₋₁>, terms of a lucas sequence with parameter τ,
 * compute <Vₕᵢ, Vₕᵢ₋₁>
 */
void
lucas(BIGNUM *v, BIGNUM *w,
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

/**
 * \brief William's p+1 factorization.
 *
 */
static RSA*
williams_question_ask_rsa(const RSA* rsa)
{
  RSA *ret = NULL;
  BIGNUM *p = BN_new();
  BIGNUM *gcd = BN_new();
  BIGNUM
    *v = BN_new(),
    *w = BN_new();
  BIGNUM *n;
  BIGNUM *tau = BN_new();
  BIGNUM *q = BN_new();
  int e, i;
  BN_CTX *ctx = BN_CTX_new();
  pit_t *pit;

  n = rsa->n;
  BN_one(gcd);
  BN_one(w); BN_uiadd1(w);
  BN_pseudo_rand(tau, 512, 0, 0);
  BN_copy(v, tau);
  /* In the future, accumulated values: BN_one(q); */

  for (pit = primes_init(); primes_next(pit, p); ) {
    e = BN_num_bits(n) / (BN_num_bits(p));
    for (i=0; i < e; i++) {
      lucas(v, w, p, tau, ctx);
      /* XXX. unsafe. */
      BN_mod(v, v, n, ctx);
      BN_mod(w, w, n, ctx);
      /* q = v - 2 */
      BN_sub(q, v, BN_value_one());
      BN_sub(q, q, BN_value_one());
      /* gcd test */
      BN_gcd(gcd, q, n, ctx);
      if (BN_cmp(gcd, BN_value_one()) == 1) goto end;
    }
  }

 end:
  BN_free(p);
  prime_iterator_free(pit);

  if (BN_ucmp(gcd, n) != 0)
    ret = qa_RSA_recover(rsa, gcd, ctx);

  return ret;
}

qa_question_t WilliamsQuestion = {
  .name = "p+1",
  .pretty_name = "Williams' p+1 factorization",
  .ask_rsa = williams_question_ask_rsa
};

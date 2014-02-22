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
      BN_sub(w, vv, BN_value_two());
    } else {
      BN_sqr(vv, v, ctx);
      /* v = v² - 2 */
      BN_sub(u, vv, BN_value_two());
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
  BIGNUM
    *v = BN_new(),
    *v2 = BN_new(),
    *w = BN_new(),
    *n = rsa->n,
    *tau = BN_new(),
    *q = BN_new(),
    *p = BN_new(),
    *g = BN_new();
  int e, k, j, m = 100;
  BN_CTX *ctx = BN_CTX_new();
  pit_t *pit;

  BN_one(g);
  BN_one(w); BN_uiadd1(w);
  BN_pseudo_rand(tau, 512, 0, 0);
  BN_copy(v, tau);
  BN_one(q);

  for (pit = primes_init();
       BN_is_one(g) && primes_next(pit, p);
       ) {
    e = BN_num_bits(n) / (BN_num_bits(p));
    for (k = 0; k < e && BN_is_one(g); k += m) {
      for (j = (m > e) ? e : m; j; j--) {
        lucas(v, w, p, tau, ctx);
        /* XXX. unsafe. */
        BN_mod(v, v, n, ctx);
        BN_mod(w, w, n, ctx);
        /* q = v - 2 */
        BN_sub(v2, v, BN_value_one());
        BN_sub(v2, v2, BN_value_one());
        BN_mod_mul(q, q, v2, n, ctx);
      }
      /* gcd test */
      BN_gcd(g, q, n, ctx);
    }
  }

  if (BN_cmp(g, n))
    ret = qa_RSA_recover(rsa, g, ctx);

  BN_free(v);
  BN_free(v2);
  BN_free(w);
  BN_free(tau);
  BN_free(p);
  BN_free(q);
  BN_free(g);
  prime_iterator_free(pit);

  return ret;
}

qa_question_t WilliamsQuestion = {
  .name = "p+1",
  .pretty_name = "Williams' p+1 factorization",
  .ask_rsa = williams_question_ask_rsa
};

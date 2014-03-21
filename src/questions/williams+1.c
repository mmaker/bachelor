/**
 * \file williams+1.c
 * \brief An implementation of William's p+1 Attack.
 *
 * William's attack, published in 1982, describes a factorization algorithm
 * based on lucas sequences and Lehmer's theorem.
 *
 */
#include "config.h"

#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "qa/questions/primes.h"
#include "qa/questions/qarith.h"
#include "qa/questions/questions.h"
#include "qa/questions/qwilliams.h"


#define MAX_ATTEMPTS 10

/**
 * \brief Lucas Sequence Multiplier.
 *
 * Given a pair <Vᵢ, Vᵢ₋₁>, terms of a lucas sequence with parameter τ,
 * compute <Vₕᵢ, Vₕᵢ₋₁>
 */
void
lucas(BIGNUM *v, BIGNUM *h,
      BIGNUM *n, BN_CTX *ctx)
{
  BIGNUM *w;
  BIGNUM *vv;
  BIGNUM *vw;
  BIGNUM *tau;
  int i;

  w = BN_new();
  vv = BN_new();
  vw = BN_new();

  tau = BN_dup(v);
  BN_mod_sqr(vv, v, n, ctx);
  BN_mod_sub(w, vv, BN_value_two(), n, ctx);

  for (i = BN_num_bits(h); !BN_is_bit_set(h, i); i--);
  for (i--; i >= 0; i--) {
    if (BN_is_bit_set(h, i)) {
      /* v = vw - τ (mod N) */
      BN_mod_mul(vw, v, w, n, ctx);
      BN_mod_sub(v, vw, tau, n, ctx);
      /* w = w² - 2 */
      BN_mod_sqr(vv, w, n, ctx);
      BN_mod_sub(w, vv, BN_value_two(), n, ctx);
    } else {
      /* w = vw - τ (mod N) */
      BN_mul(vw, v, w, ctx);
      BN_mod_sub(w, vw, tau, n, ctx);
      /* v = v² - 2 */
      BN_mod_sqr(vv, v, n, ctx);
      BN_mod_sub(v, vv, BN_value_two(), n, ctx);
    }
  }

  BN_free(w);
  BN_free(tau);
  BN_free(vv);
  BN_free(vw);
}

static BIGNUM*
williams_factorize(BIGNUM *n, BIGNUM *v, BN_CTX *ctx)
{
  BIGNUM *ret = NULL;
  BIGNUM
    *v2 = BN_new(),
    *q = BN_new(),
    *p = BN_new(),
    *g = BN_new();
  int e, k, j, m = 100;
  pit_t *pit;
  struct {
    BIGNUM *p;
    BIGNUM *v;
    int k;
  } back = {BN_new(), BN_new(), 0};

  BN_copy(back.v, v);
  BN_copy(back.p, BN_value_two());

  BN_one(g);
  BN_one(q);
  for (pit = primes_init();
       BN_is_one(g) && primes_next(pit, p);
       ) {
#ifdef DEBUG
    fprintf(stderr, "Testing prime: ");
    BN_print_fp(stderr, p);
    fprintf(stderr, "\r");
#endif

    e = 10; // BN_num_bits(n) / BN_num_bits(p) + 1;
    for (k = 0; k < e && BN_is_one(g); k += m) {
      for (j = (m > e) ? e : m; j; j--) {
        lucas(v, p, n, ctx);
        /* q = v - 2 */
        BN_mod_sub(v2, v, BN_value_two(), n, ctx);
        BN_mod_mul(q, q, v2, n, ctx);
      }
      /* gcd test */
      BN_gcd(g, q, n, ctx);

      if (BN_is_one(g)) {
        BN_copy(back.p, p);
        BN_copy(back.v, v);
        back.k = k;
      }
    }
  }

  if (!BN_cmp(g, n)) {
#ifdef DEBUG
    printf("rollback!\n");
#endif
    BN_copy(p, back.p);
    BN_one(g);
    BN_copy(v, back.v);
    e = BN_num_bits(n) / BN_num_bits(p) + 5;
    for (k = back.k; k < e; k++) {
      lucas(v, p, n, ctx);
      BN_sub(v2, v, BN_value_two());
      BN_gcd(g, v2, n, ctx);
      if (!BN_is_one(g)) break;
    }
  }
  if (!BN_is_one(g) && BN_cmp(g, n))
    ret = g;
  else
    BN_free(g);

  BN_free(back.v);
  BN_free(back.p);
  BN_free(v2);
  BN_free(p);
  BN_free(q);
  prime_iterator_free(pit);

  return ret;
}

/**
 * \brief William's p+1 factorization.
 *
 */
static RSA*
williams_question_ask_rsa(const RSA* rsa)
{
  int i;
  BIGNUM* v = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *g;
  RSA *ret = NULL;

  for (i=0; !ret &&  i!= MAX_ATTEMPTS; i++) {
    BN_pseudo_rand_range(v, rsa->n);
    g = williams_factorize(rsa->n, v, ctx);
    if (g)
      ret = qa_RSA_recover(rsa, g, ctx);
  }

  BN_free(v);
  BN_CTX_free(ctx);
  return ret;
}



qa_question_t WilliamsQuestion = {
  .name = "p+1",
  .pretty_name = "Williams' p+1 factorization",
  .ask_rsa = williams_question_ask_rsa
};

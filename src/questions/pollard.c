/**
 * \file pollard.c
 *
 * \brief Pollard's (p-1) factorization algorithm.
 *
 * This file contains an implementations of Pollard's (p-1) algorithm, used to
 * attack the public modulus of RSA.
 *
 * Consider the public modulus N = pq. Now,
 *  (p-1) = q₀ᵉ⁰q₁ᵉ¹… qₖᵉᵏ .  q₀ᵉ⁰ < q₁ᵉ¹ < … < qₖᵉᵏ ≤ B
 * implies that  (p-1) | B! , since all factors of (p-1) belongs to {1, …, B}.
 * Consider a ≡ 2^(B!) (mod N)
 *   a = 2^(B!) + kN  = 2^(B!) + kqp → a ≡ 2^(B!) (mod p)
 * Since
 * <pre>
 *
 *   ⎧ 2ᵖ⁻¹ ≡ 1 (mod p)                              ⎧ p | (a-1)
 *   ⎨                  →  a ≡ 2^(B!) ≡ 1 (mod p) →  ⎨           → p | gcd(a-1, N)
 *   ⎩ p-1 | B!                                      ⎩ p | N
 *
 * </pre>
 * And gcd(a-1, N) is a non-trivial factor of N, unless a = 1.
 */

#include <openssl/x509.h>
#include <openssl/err.h>

#include "qa/questions/questions.h"
#include "qa/questions/primes.h"
#include "qa/questions/qarith.h"
#include "qa/questions/qpollard.h"

/* limits of primes. NOT used in cluster. */
#define PRIMES_LIM 1000

/**
 * \brief Pollard (p-1) factorization.
 *
 */
static RSA*
pollard1_question_ask_rsa(const RSA* rsa)
{
  RSA *ret = NULL;
  BIGNUM
    *p = BN_new(),
    *b = BN_new(),
    *b1 = BN_new(),
    *q = BN_new(),
    *r = BN_new(),
    *g = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  pit_t *it;
  long j;
  struct {
    BIGNUM *p;
    BIGNUM *b;
    int k;
  } back = {BN_new(), BN_new(), 0};

  int e, k, m = 100;

  BN_pseudo_rand_range(b, rsa->n);
  /* initialize backup */
  BN_copy(back.p, BN_value_two());
  BN_copy(back.b, b);

  BN_one(g);
  BN_one(q);
#ifdef HAVE_OPENMPI
  for (it = primes_init();
       BN_is_one(g) && primes_next(it, p);
       ) {
#else
  it = primes_init();
  for (int lim=PRIMES_LIM;
       lim && BN_is_one(g) && primes_next(it, p);
       lim--) {
#endif

    e = BN_num_bits(rsa->n) / BN_num_bits(p) + 1;
    for (k = 0; k < e && BN_is_one(g); k += m) {
      for (j = (m > e) ? e : m; j; j--) {
        BN_mod_exp(b, b, p, rsa->n, ctx);
        BN_sub(b1, b, BN_value_one());
        BN_mod_mul(q, q, b1, rsa->n, ctx);
      }
      BN_gcd(g, q, rsa->n, ctx);

      /* epoch ended: backup */
      if (BN_is_one(g)) {
        BN_copy(back.p, p);
        BN_copy(back.b, b);
        back.k = k;
      }
    }
  }

  /* replay latest epoch */
  if (!BN_cmp(g, rsa->n)) {
#ifdef DEBUG
    fprintf(stderr, "rollback!\n");
#endif
    BN_copy(p, back.p);
    BN_one(g);
    BN_copy(b, back.b);
    e = BN_num_bits(rsa->n) / BN_num_bits(p) + 1;
    for (k = back.k; k < e; k++) {
      BN_mod_exp(b, b, p, rsa->n, ctx);
      BN_sub(b1, b, BN_value_one());
      BN_gcd(g, b1, rsa->n, ctx);
      if (BN_is_one(g)) break;
    }
  }

  if (BN_cmp(g, rsa->n) && !BN_is_one(g))
      ret = qa_RSA_recover(rsa, g, ctx);

  BN_free(back.p);
  BN_free(back.b);
  BN_free(p);
  BN_free(q);
  BN_free(b);
  BN_free(b1);
  BN_free(r);
  BN_free(g);
  BN_CTX_free(ctx);

  return ret;
}



qa_question_t PollardQuestion = {
  .name = "p-1",
  .pretty_name = "Pollard's (p-1) factorization",
  .setup = NULL,
  .teardown = NULL,
  .test = NULL,
  .ask_rsa = pollard1_question_ask_rsa,
  .ask_crt = NULL
};

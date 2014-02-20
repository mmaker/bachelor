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


static BIGNUM *two = NULL;

static int
pollard1_question_setup(void)
{
  /* create 2 */
  BN_dec2bn(&two, "2");
  return 1;
}

static int
pollard1_question_teardown(void)
{
  BN_free(two);
  return 1;
}

/**
 * \brief Pollard (p-1) factorization.
 *
 */
static RSA*
pollard1_question_ask_rsa(const RSA* rsa)
{
  RSA *ret = NULL;
  BIGNUM *p = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *r = BN_new();
  BIGNUM *gcd = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  pit_t *it;
  long thresh = 1 << 20;
  int e;

  BN_pseudo_rand_range(b, rsa->n);
  it=primes_init();
  for (primes_next(it, p); thresh-- ; primes_next(it, p))  {
    e = BN_num_bits(rsa->n) / BN_num_bits(p);
    while (e-- && !ret) {
      /* XXX. unsafe. */
      BN_mod_exp(b, b, p, rsa->n, ctx);
      BN_sub(q, b, BN_value_one());
      BN_gcd(gcd, q, rsa->n, ctx);
      if (BN_cmp(gcd, rsa->n) && BN_cmp(gcd, BN_value_one()))
          ret = qa_RSA_recover(rsa, gcd, ctx);
    }
  }

  BN_free(p);
  BN_free(q);
  BN_free(b);
  BN_free(r);
  BN_free(gcd);
  BN_CTX_free(ctx);

  return ret;
}

/**
 * \brief Pollard (p-1) factorization.
 *
 * Trivially the algorithm computes a = 2^(B!) (mod N), and then verifies that
 * gcd(a-1, N) is a nontrivial factor of N.
 *
 * According to Wikipedia™,
 * « By Dixon's theorem, the probability that the largest factor of such a
 * number is less than (p − 1)^ε is roughly ε^(−ε); so there is a probability of
 * about 3^(−3) = 1/27 that a B value of n^(1/6) will yield a factorisation.»
 *
 */
static RSA*
naive_pollard1_question_ask_rsa(const RSA *rsa)
{
  RSA *ret = NULL;
  BIGNUM *a, *B, *a1;
  BIGNUM *gcd, *rem;
  BIGNUM *n;
  BN_CTX *ctx;

  n = rsa->n;
  a = BN_new();
  B = BN_new();
  a1 = BN_new();
  gcd = BN_new();
  rem = BN_new();
  ctx = BN_CTX_new();

  /* take ⁸√N */
  BN_sqrtmod(gcd, rem, n, NULL);
  BN_sqrtmod(B, rem, gcd, NULL);
  /* compute 2^(B!) */
  for (BN_copy(a, two), BN_one(gcd);
       !(BN_is_zero(B) || !BN_is_one(gcd) || BN_cmp(gcd, n)==0);
       BN_usub(B, B, BN_value_one())) {

    BN_mod_exp(a, a, B, n, ctx);
    /* p ≟ gcd(a-1, N) */
    BN_usub(a1, a, BN_value_one());
    BN_gcd(gcd, a1, n, ctx);
  }

  /* Either p or q found :) */
  if (!BN_is_zero(B))
    ret = qa_RSA_recover(rsa, gcd, ctx);

  BN_free(a);
  BN_free(B);
  BN_free(a1);
  BN_free(gcd);
  BN_free(rem);
  BN_CTX_free(ctx);

  return ret;
}


qa_question_t PollardQuestion = {
  .name = "p-1",
  .pretty_name = "Pollard's (p-1) factorization",
  .setup = pollard1_question_setup,
  .teardown = pollard1_question_teardown,
  .test = NULL,
  .ask_rsa = pollard1_question_ask_rsa,
  .ask_crt = NULL
};

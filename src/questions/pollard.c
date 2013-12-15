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
#include "qa/questions/qarith.h"
#include "qa/questions/qpollard.h"


static BIGNUM *two;

int pollard1_question_setup(void)
{
  /* create 2 */
  two = BN_new();
  BN_one(two);
  BN_uadd(two, two, BN_value_one());
  return 0;
}

int pollard1_question_teardown(void)
{
  BN_free(two);
  return 0;
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
int pollard1_question_ask_rsa(RSA *rsa)
{
  int ret = 1;
  BIGNUM *a, *B, *a1;
  BIGNUM *gcd, *rem;
  BIGNUM *n;
  BIGNUM *p, *q;
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
  ret = BN_is_zero(B);
  if (!ret) {
    p = BN_dup(gcd);
    q = BN_new();
    BN_div(q, NULL, n, gcd, ctx);
    printf("p:%s, q=%s \n", BN_bn2dec(p), BN_bn2dec(q));
  }

  BN_free(a);
  BN_free(B);
  BN_free(a1);
  BN_free(gcd);
  BN_free(rem);
  BN_CTX_free(ctx);

  return ret;
}


struct qa_question PollardQuestion = {
  .name = "Pollard's (p-1) factorization",
  .setup = pollard1_question_setup,
  .teardown = pollard1_question_teardown,
  .test = NULL,
  .ask_rsa = pollard1_question_ask_rsa,
  .ask_crt = NULL
};

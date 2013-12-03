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

#include "questions.h"

int pollard1_question_setup(void)
{
  return 0;
}

int pollard1_question_teardown(void)
{
  return 0;
}


int pollard1_question_test(X509 *cert)
{
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
int pollard1_question_ask(X509 *cert)
{
  RSA *rsa;
  BIGNUM *a, *B;
  BIGNUM *n;

  rsa = X509_get_pubkey(cert)->pkey.rsa;
  n = rsa->n;
  a = BN_new();
  B = BN_new();

  BN_dec2bn(&a, "2");

  BN_free(a);
  BN_free(B);

  return 0;
}


struct qa_question PollardQuestion = {
  .name = "Pollard's (p-1) factorization",
  .setup = pollard1_question_setup,
  .teardown = pollard1_question_teardown,
  .test = pollard1_question_test,
  .ask = pollard1_question_ask,
};

/**
 * \file dixon.c
 * \brief An implementation of Dixon's Attack using bignums.
 *
 * Given a non-empty set B of primes, called factor-base, and
 * given a non-empty set of random numbers R, s.t. ∀ r ∈ R,  s ≡ r² (mod N) is B-smooth.
 *
 * Try to find
 *   U ⊂ R | (Πᵤ rᵢ)² ≡ Π s (mod N) and by defining x ≝ Πᵤ rᵢ, y ≝ √(Π s)
 *                 x² ≡ y² (mod N)
 * Asserting that x ≢ y (mod N) we claim to have found the two non-trivial
 * factors of N by computing gcd(x+y, N) and gcd(x-y, N).
 *
 * \note N = pq is assumed to be the public modulus,
 * while e, d . ed ≡ 1 (mod φ(N))  are respectively the public and the private
 * exponent.
 */

#include <stdlib.h>

#include <openssl/bn.h>

#include "questions.h"


#define BPOOL_EXTEND_STEP   42
#define BPOOL_STARTING_BITS  7
#define RPOOL_EXTEND_STEP   42

#define qa_rand rand

/**
 * \struct dixon_number_t
 * \brief Auxiliary structure holding informations for R_pool.
 */
typedef struct dixon_number {
  BIGNUM *r;   /**< the random number which have been chosen */
  BIGNUM *s;   /**< s ≡ r² (mod N) */
  BIGNUM **v;   /**< a cached vectors holding the exponents for the prime
                 * factorization of s. */
} dixon_number_t;

/** Pool of random numbers, i.e. the set R. */
dixon_number_t *R_pool = NULL;

static size_t R_size = 0;

/** Pool of prime numbers, i.e. B, the factor base. */
static BIGNUM** B_pool = NULL;
static size_t B_size = 0;


static void extend_B_pool(int max_bits)
{
  size_t i, old_B_size;
  int bits;

  old_B_size = B_size;
  B_size += BPOOL_EXTEND_STEP;

  B_pool = realloc(B_pool, B_size * sizeof(BIGNUM*));

  for (i=old_B_size; i!=B_size; i++) {
    bits = 1 + qa_rand() % max_bits;
    B_pool[i] = BN_generate_prime(NULL, bits, 0, NULL, NULL, NULL, NULL);
  }
  /* XXX. reallocate space for vectors in R_pool */
}

#define B_pool_free() free(B_pool)

/**
 * We have two possible choices here, for generating a valid random rumber
 * satisfying Dixon's theorem requirements.
 *
 * Alg. 1 - 1. Start by generating a random r such that r > √N,
 *          2. Calculate s ≡ r² (mod N)
 *          3. Factorize s using B and see if that's B-smooth
 * This algorithm shall have complexity O(k + N² + |B|lg N)
 *
 * Alg. 2 - 1. Generate the random exponents for s, {e₀, e₁, …, eₘ} where m = |B|
 *          2. From the generated exponents, calculate s = p₀^e₀·p₁^e₁·…·pₘ^eₘ
 *             knowing that s < N
 *          3. Find an r = √(s + tN) , t ∈ {1..N-1}
 * This algorithm shall have complexity O(k|B| + (N-1)lg N)
 */
static void extend_R_pool(BIGNUM* max_s)
{
  size_t i, j;
  dixon_number_t *d;

  i = R_size;
  R_size += RPOOL_EXTEND_STEP;
  R_pool = realloc(R_pool, sizeof(dixon_number_t));

  for (; i!= R_size; i++) {
    d = &R_pool[i];
    d->s = BN_new();
    /* generate exponents and calculate s */
    while (BN_cmp(d->s, max_s) != -1) {
      for (j=0; j != B_size; j++) {
        ;
      }
    }
  }

}
#define R_pool_free() free(R_pool)

int dixon_question_setup(void)
{
  extend_B_pool(BPOOL_STARTING_BITS);
  extend_R_pool();
  return 0;
}

int dixon_question_teardown(void) {
  B_pool_free();
  R_pool_free();
  return 0;
}

int dixon_question_test(X509* cert) { return 1; }

int dixon_question_ask(X509* cert) {

  return 0;
}

qa_question_t DixonQuestion = {
  .name = "Dixon",
  .setup = dixon_question_setup,
  .teardown = dixon_question_teardown,
  .test = dixon_question_test,
  .ask = dixon_question_ask
};

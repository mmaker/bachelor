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

#include <assert.h>
#include <stdlib.h>
#include <strings.h>

#include <openssl/bn.h>

#include "qa/questions/qarith.h"
#include "qa/questions/qstrings.h"
#include "qa/questions/questions.h"

#define EPOCHS             100
#define REPOP_EPOCHS        50
#define BPOOL_EXTEND_STEP   42
#define BPOOL_STARTING_BITS  7
#define RPOOL_EXTEND_STEP   42
#define U_SIZE              10

#define qa_rand rand

static BIGNUM* zero;

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


/**
 * \brief Extends the factor base, and then adjusts R_pool
 *
 */
static void extend_B_pool(int max_bits)
{
  size_t i, j, old_B_size;
  int bits;

  old_B_size = B_size;
  B_size += BPOOL_EXTEND_STEP;
  /* check for size_t overflow */
  assert(old_B_size < B_size);

  B_pool = realloc(B_pool, B_size * sizeof(BIGNUM*));

  for (i=old_B_size; i!=B_size; i++) {
    bits = 1 + qa_rand() % max_bits;
    B_pool[i] = BN_generate_prime(NULL, bits, 0, NULL, NULL, NULL, NULL);
  }
  /* reallocate space for vectors in R_pool */
  for (i=0; i!=R_size; i++) {
    R_pool[i].v = realloc(R_pool[i].v, sizeof(BIGNUM*) * B_size);
    for (j=old_B_size; j!=B_size; j++) R_pool[i].v[j] = NULL;
  }
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
static void extend_R_pool(BIGNUM* N)
{
  const size_t old_R_size = R_size;
  size_t i, j;
  int e_bits;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM
    *e,
    *tmp = BN_new(),
    *rem = BN_new(),
    *t = BN_new();
  dixon_number_t *d;

  R_size += RPOOL_EXTEND_STEP;
  /* size_t overflow */
  assert(R_size > old_R_size);
  R_pool = realloc(R_pool, sizeof(dixon_number_t));
  /*
   * XXX. There is much more to think about this.
   * We are trying to generate some random exponents e₀…eₖ such that s < N .
   * Hence, log(N) = ae₀ + be₁ + … + leₖ
   */
  e_bits = BN_num_bits(N) / 5;

  for (i=old_R_size; i!= R_size; i++) {
    d = &R_pool[i];
    d->s = BN_new();
    d->r = BN_new();

    /* generate exponents and calculate s */
    for (j=0; j != B_size && BN_cmp(N, d->s) == 1; j++) {
      e = d->v[j] = BN_new();
      /* XXX. better check for error here. */
      BN_pseudo_rand(e, e_bits, -1, 0);
      BN_exp(tmp, B_pool[j], e, ctx);
      BN_mul(d->s, tmp, d->s, ctx);
    }

    /*  Find an r = √(s + tN) , t ∈ {1..N-1} */
    BN_sqr(tmp, N, ctx);
    BN_one(t);
    for (BN_add(t, t, N); BN_cmp(tmp, t) == 1; BN_add(t, t, N))
      if (BN_sqrtmod(d->r, rem, t, ctx)) break;
  }


  BN_CTX_free(ctx);
  BN_free(rem);
  BN_free(tmp);
  BN_free(t);

}


#define R_pool_free() free(R_pool)

int dixon_question_setup(void)
{
  extern BIGNUM* zero;
  zero = BN_new();
  BN_zero(zero);

  extend_B_pool(BPOOL_STARTING_BITS);
  return 0;
}

int dixon_question_teardown(void) {
  BN_free(zero);

  B_pool_free();
  R_pool_free();
  return 0;
}

int dixon_question_test(X509* cert) {
  return 1;
}


int dixon_question_ask(X509* cert) {
  RSA *rsa;
  /* key data */
  BIGNUM
    *n, *e,
    *p, *q;
  /* x, y */
  BIGNUM
    *x, *x2,
    *y, *y2;
  BN_CTX *ctx;
  /* U ⊆ R */
  ssize_t *U_bucket;
  /* internal data */
  int epoch;
  BIGNUM *tmp;
  char *even_powers;
  size_t i, j, k;

  rsa = X509_get_pubkey(cert)->pkey.rsa;
  n = rsa->n;
  e = rsa->e;
  U_bucket = malloc(sizeof(ssize_t) * U_SIZE);
  even_powers = malloc(sizeof(char) * B_size);
  ctx = BN_CTX_new();
  x = BN_new();
  y = BN_new();
  x2 = BN_new();
  y2 = BN_new();
  tmp = BN_new();

  /* mainloop: iterate until a key is found, or convergence. */
  for (epoch=0; epoch < EPOCHS; epoch++) {
    /* depending on the epoch, populate R_pool and B_pool */
    if (epoch % REPOP_EPOCHS) extend_R_pool(n);

    /* reset variables */
    for (i=0; i!=U_SIZE; i++) U_bucket[i] =  -1;
    bzero(even_powers, B_size * sizeof(char));
    j = 0;

    /* choose a subset of R such that the product of primes can be squared */
    do {
      for (i=0; i!=B_size && j < U_SIZE; i++) {
        /* choose whether to take or not R_pool[i] */
        if (qa_rand() % 2) continue;

        /* add the number */
        U_bucket[j++] = i;
        for (k=0; k!=B_size; k++)
          even_powers[k] ^= BN_is_odd(R_pool[i].v[j]);
      }
    } while (!is_vzero(even_powers, B_size * sizeof(char)));

    /* let x = Πᵢ rᵢ , y² = Πᵢ sᵢ */
    BN_one(x);
    BN_one(y2);
    for (i=0; i != U_SIZE; i++) {
      if (U_bucket[i] == -1) continue;

      j = U_bucket[i];
      BN_mul(x, x, R_pool[j].r, ctx);
      BN_mul(y2, y2, R_pool[j].s, ctx);
    }
    /* retrieve x² from x */
    BN_sqr(x2, x, ctx);
    /* retrieve y from y² */
    /* test: shall *always* be a perfect square */
    if (!BN_sqrtmod(y, tmp, y2, ctx)) continue;
    /* test: assert that x ≡ y (mod N) */
    if (!BN_cmp(x, y)) continue;

    /* p, q found :) */
    p = BN_new();
    q = BN_new();

    BN_uadd(tmp, x, y);
    BN_gcd(p, tmp, n, ctx);
    assert(!BN_is_one(p) && BN_cmp(p, n));
    BN_usub(tmp, x, y);
    BN_gcd(q, tmp, n, ctx);
    assert(!BN_is_one(q) && BN_cmp(q, n));
  }

  BN_free(x);
  BN_free(x2);
  BN_free(y);
  BN_free(y2);
  free(U_bucket);
  free(even_powers);

  return 0;
}

qa_question_t DixonQuestion = {
  .name = "Dixon",
  .setup = dixon_question_setup,
  .teardown = dixon_question_teardown,
  .test = dixon_question_test,
  .ask = dixon_question_ask
};

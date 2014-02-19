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

#include <stdint.h>
#include <strings.h>

#include <openssl/bn.h>

#include "qa/questions/questions.h"
#include "qa/questions/qstrings.h"
#include "qa/questions/qdixon.h"


matrix_t*
identity_matrix_new(int d)
{
  size_t i;
  matrix_t *m  = matrix_new(d, d);


  for (i=0; i!=d; i++) {
    bzero(m->M[i], sizeof(**(m->M)) * d);
    m->M[i][i] = 1;
  }

  return m;
}


matrix_t*
matrix_new(int r, int c)
{
  matrix_t *m;
  size_t i;

  m = malloc(sizeof(matrix_t));
  m->f = r;
  m->r = c;
  m->M = malloc(sizeof(BIGNUM **) * m->f);
  for (i=0; i!=r; i++)
    m->M[i] = malloc(sizeof(BIGNUM*) * m->r);

  return m;
}

void
matrix_free(matrix_t *m)
{
  size_t i;

  for (i=0; i!= m->f; i++)
    free(m->M[i]);
  free(m->M);
  free(m);
}

/*
 * \ref Kernel into a binary matrix.
 *
 * Discover linear dependencies using a refined version of the Gauss-Jordan
 * algorithm, from Brillhart and Morrison.
 *
 * \return h, the history matrix
 *
 */
matrix_t *
kernel(matrix_t *m)
{
  int i, j, k;
  matrix_t *h = identity_matrix_new(m->f);

  for (j=0; j!=m->r; j++)
    for (i=0;  i != m->f; i++)
      if (m->M[i][j]) {
        for (k=i+1; k != m->f; k++)
          if (m->M[k][j]) {
            vxor(m->M[k], m->M[k], m->M[i], m->r);
            vxor(h->M[k], h->M[k], h->M[i], h->r);
          }
        break;
      }

  return h;
}

qa_question_t DixonQuestion = {
  .name = "dixon",
  .pretty_name = "Dixon's Factorization"
};

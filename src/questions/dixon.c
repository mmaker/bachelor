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
#include "config.h"

#include <assert.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/bn.h>

#ifdef HAVE_OPENMPI
#include <mpi.h>
#endif

#include "qa/questions/questions.h"
#include "qa/questions/primes.h"
#include "qa/questions/qarith.h"
#include "qa/questions/qstrings.h"
#include "qa/questions/qdixon.h"


#ifdef HAVE_OPENMPI
#define ENCLEN 2048

MPI_Datatype MPI_BNPAIR;

#endif

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
  int i, j, rg;
  matrix_t *h = identity_matrix_new(m->f);

  rg = 0;
  for (j=0; j!=m->r; j++)
    for (i=rg;  i != m->f; i++)
      if (m->M[i][j]) {
        vswap(m->M[i], m->M[rg], m->r);
        vswap(h->M[i], h->M[rg], h->r);

        for (i=rg+1; i < m->f; i++)
          if (m->M[i][j]) {
            vxor(m->M[i], m->M[i], m->M[rg], m->r);
            vxor(h->M[i], h->M[i], h->M[rg], h->r);
          }
        rg++;
        break;
      }

  return h;
}


/**
 * \brief Check for smoothness, incuding negative numbers.
 *
 * As there is no reason to reject negative numbers, provided that the product is positive, we are going to include the sign into the fist element of `v`, as to indicate the sign.
 */
int dixon_smooth(BIGNUM *y, BN_CTX *ctx, char *v, size_t len)
{
  short neg, ret;

  /* is yᵢ smooth? */
  neg = BN_is_negative(y);
  if (neg) BN_set_negative(y, 0);
  ret = smooth(y, ctx, v+1, len-1);
  if (neg) BN_set_negative(y, 1);
  v[0] = neg;

  return ret;
}

/**
 * \brief Discover a number x such that x² - n is smooth.
 *
 */
inline void
discover_smooth(BIGNUM *y, BIGNUM *x, BIGNUM *n,
                BN_CTX *ctx, char *v, size_t len)
{
  do {
    BN_pseudo_rand_range(x, n);
    /* yᵢ = xᵢ² - N */
    BN_sqr(y, x, ctx);
    BN_sub(y, y, n);

  } while (!dixon_smooth(y, ctx, v, len));
}


RSA*
dixon_factorize(const RSA *rsa)
{
  /*
   * take exp(sqrt(ln N ln ln N))
   *    ≅ 1.44 * 2^(sqrt(lg N lg lg N))
   *    ≅ ³/₂ * 2^(sqrt(lg N 10)) for keys of 1024 bits.
   */
  size_t primes = 3 * (1 << (BN_num_bits(rsa->n) * 5)) / 2;
  size_t f = primes + 5;
  size_t r = primes + 1;
  size_t i, j;
  RSA *ret = NULL;
  BIGNUM
    *x = BN_new(),
    *y = BN_new(),
    *sqy = BN_new(),
    *rem = BN_new(),
    *gcd = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  struct bnpair {
    BIGNUM *x;
    BIGNUM *y;
  } *R = NULL;
  matrix_t *m = NULL;
  matrix_t *h;


#ifndef HAVE_OPENMPI
  /** STEP 1: initialization **/
  /* plus one for the sign */
  m = matrix_new(f, r);
  R = malloc(sizeof(struct bnpair) * f);
  for (i=0; i!=f; i++) {
    R[i].x = BN_new();
    R[i].y = BN_new();
  }

  /** STEP 2 generating R */
  for (i=0; i < m->f; i++) {
    fprintf(stderr, "[!] Discovering %zdth smooth number\n", i);
    discover_smooth(R[i].y, R[i].x, rsa->n,
                    ctx, m->M[i], m->r);
  }
#else
  int procs, proc;
  int count;
  MPI_Comm_rank(MPI_COMM_WORLD, &proc);
  MPI_Comm_size(MPI_COMM_WORLD, &procs);
  struct {
    char x[ENCLEN];
    char y[ENCLEN];
    char v[r];
  } to;

  MPI_Aint offsets[3] = {0, ENCLEN, 2*ENCLEN};
  MPI_Datatype types[3] = {MPI_CHAR, MPI_CHAR, MPI_CHAR};
  int lengths[3] = {ENCLEN, ENCLEN, r};
  MPI_Type_struct(3, lengths, offsets, types, &MPI_BNPAIR);
  MPI_Type_commit(&MPI_BNPAIR);

  /* root node fetches, child nodes discovery */
  if (proc == 0) {
    /** STEP 1: initialization **/
    m = matrix_new(f, r);
    R = malloc(sizeof(struct bnpair) * f);

    /** STEP 2 generating R */
    count = procs > 1 ? f % (procs-1) : f;
    for (i=0; i != f - count; i++) {
      MPI_Recv(&to, 1, MPI_BNPAIR, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
      R[i].x = BN_new();
      R[i].y = BN_new();
      BN_hex2bn(&R[i].x, to.x);
      BN_hex2bn(&R[i].y, to.y);
      memcpy(m->M[i], to.v, r);

      fprintf(stderr, "[!] discovering relations (%zu/%zu)\r", i, f);
    }

    for (;i < f; i++) {
      R[i].x = BN_new();
      R[i].y = BN_new();
      discover_smooth(R[i].y, R[i].x, rsa->n, ctx, m->M[i], r);
    }
  } else {
    BIGNUM *x = BN_new(), *y = BN_new();
    char *s;

    for (count = f / (procs-1); count; count--) {
      discover_smooth(y, x, rsa->n, ctx, to.v, r);
      s = BN_bn2hex(x);
      strcpy(to.x, s);
      OPENSSL_free(s);
      s = BN_bn2hex(y);
      strcpy(to.y, s);
      OPENSSL_free(s);

      /* fprintf(stderr, "generated: %s (%d)", to.x, count); */
      MPI_Send(&to, 1, MPI_BNPAIR, 0, 0, MPI_COMM_WORLD);
    }
    BN_free(x);
    BN_free(y);
  }

  if (proc != 0) {
    MPI_Finalize();
    exit(EXIT_SUCCESS);
  }
#endif

  fprintf(stderr, "\n[!] breaching the kernel\n");
  /** STEP 3: break & enter. */
  h = kernel(m);
  for (i = h->f - 1;
       !ret && is_vzero(m->M[i], h->r);
       i--) {
    BN_one(x);
    BN_one(sqy);
    /* if we found an even power */
    fprintf(stderr, "[!] Examining relation\n");
    /* compute x, y² */
    for (j=0; j!=h->r; j++)
      if (h->M[i][j]) {
        BN_mul(x, x, R[j].x, ctx);
        BN_mul(sqy, sqy, R[j].y, ctx);
      }
    BN_sqrtmod(y, rem, sqy, ctx);
    //  assert(!BN_is_zero(rem));
    BN_gcd(gcd, x, y, ctx);
    if (BN_cmp(gcd, rsa->n) < 0 &&
        BN_cmp(gcd, BN_value_one()) > 0)
      ret = qa_RSA_recover(rsa, gcd, ctx);
  }

  /* free all the shit */
  for (i=0; i!=f; i++) {
    BN_free(R[i].x);
    BN_free(R[i].y);
  }
  free(R);
  BN_free(x);
  BN_free(y);
  BN_free(sqy);
  BN_free(rem);
  BN_free(gcd);
  BN_CTX_free(ctx);
  matrix_free(m);

  return ret;
}


/**
 * \brief Measuring the strength of a RSA key.
 *
 * Note that I assume this function to be shit. I did not have had enough time
 * to discuss this with my professor, and furthermore I believe this to be an
 * incorrect measure: inaffidable, defective, and misleading. It is being
 * written anyway in order to make him happy.
 */
static RSA*
dixon_question_ask_rsa(const RSA* rsa)
{
#ifdef HAVE_OPENMPI
  return dixon_factorize(rsa);
#else
  time_t start, end;
  /* see factorization function */
  int primes = 3 * (BN_num_bits(rsa->n) * 10) / 2;
  BIGNUM
    *x = BN_new(),
    *y = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  char *v;
  int count;
  static const int wait = 60;


  v = malloc(sizeof(char) * primes);
  /* XXX. control error (return -1) here. */
  time(&start);
  end = start;
  for (count = 0; end - wait < start; time(&end)) {
    fprintf(stderr, "discovering: %dth..\r", count);
    BN_pseudo_rand_range(x, rsa->n);
    /* yᵢ = xᵢ² - N */
    BN_sqr(y, x, ctx);
    BN_sub(y, y, rsa->n);

    if (dixon_smooth(y, ctx, v, primes)) count++;
  }

  fprintf(stderr,
          "\nIn %.2f minutes %d smooth numbers"
          "have been discovered\n", (float) end - start, count);

  BN_CTX_free(ctx);
  BN_free(x);
  BN_free(y);
  return NULL;
#endif
}
qa_question_t DixonQuestion = {
  .name = "dixon",
  .pretty_name = "Dixon's Factorization",
  .ask_rsa = dixon_question_ask_rsa
};

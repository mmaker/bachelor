#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>

#include "qa/questions/qdixon.h"
#include "qa/questions/qstrings.h"


void test_matrix(void)
{
  matrix_t* m;

  m = matrix_new(2,3);
  assert(m->f == 2);
  assert(m->r == 3);
  matrix_free(m);

  m = identity_matrix_new(5);
  assert(m->f == 5);
  assert(m->r == 5);
  assert(m->M[0][0] == 1);
  assert(m->M[1][0] == 0);
  assert(m->M[3][3] == 1);
  matrix_free(m);
}


void
test_kernel(void)
{
  matrix_t *m;
  matrix_t *h;


  /* test with a canonical base in (𝔽₂)³ */
  m = identity_matrix_new(3);
  assert(m->M[0][0] == 1);
  h = kernel(m);

  assert(m->M[0][0] == 1);
  assert(!is_vzero(m->M[0], 3));
  assert(!is_vzero(m->M[1], 3));
  assert(!is_vzero(m->M[2], 3));

  matrix_free(m);
  matrix_free(h);

  /* test with a redundant system */
  m = matrix_new(4, 3);
  memcpy(m->M[0], "\0\1\0", 3);
  memcpy(m->M[1], "\0\1\1", 3);
  memcpy(m->M[2], "\0\1\1", 3);
  memcpy(m->M[3], "\0\1\1", 3);
  h = kernel(m);
  /* only two vectors are linearly independent */
  assert(!is_vzero(m->M[0], 3));
  assert(!is_vzero(m->M[1], 3));
  assert(is_vzero(m->M[2], 3));
  assert(is_vzero(m->M[3], 3));
  /* test history matrix */
  assert(h->M[0][0] == 1 && h->M[0][1] == 0);
  assert(h->M[1][1] == 1 && h->M[1][0] == 1);
  assert(h->M[2][1] == 1 && h->M[2][2] == 1);
  assert(h->f == 4 && h->r == 4);
  assert(h->M[3][2] == 0);
}

void
test_dixon_smooth(void)
{
  BIGNUM *n = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  char v[50];


  BN_dec2bn(&n, "-2");
  assert(dixon_smooth(n, ctx, v, 50));
  assert(v[0] == 1);
  assert(v[1] == 1);

  BN_dec2bn(&n, "-12");
  assert(dixon_smooth(n, ctx, v, 50));
  assert(v[0] == 1);
  assert(v[1] == 0);
  assert(v[2] == 1);

  BN_free(n);
  return;
}

int
main(int argc, char **argv)
{
  test_matrix();
  test_kernel();
  test_dixon_smooth();

  return 0;
}

#include <stdint.h>
#include <unistd.h>
#include <assert.h>

#include "qa/questions/qdixon.h"


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

int
main(int argc, char **argv)
{
  test_matrix();

  return 0;
}

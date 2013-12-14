#include <stddef.h>
#include <assert.h>

#include "qstrings.h"


void test_is_vzero(void)
{
  const char *v = "\x0\x0\x0\x1\x0\x1";

  assert(is_vzero(v, 3));
  assert(!is_vzero(v, 4));
  assert(!is_vzero(v, 6));
}

int main(int argc, char **argv)
{
  test_is_vzero();
  return 0;
}

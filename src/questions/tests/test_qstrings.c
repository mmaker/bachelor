#include <stddef.h>
#include <assert.h>

#include "qa/questions/qstrings.h"

void test_is_vzero(void)
{
  const char *v = "\x0\x0\x0\x1\x0\x1";

  assert(is_vzero(v, 3));
  assert(!is_vzero(v, 4));
  assert(!is_vzero(v, 6));
}


void test_vxor(void)
{
  size_t i;
  char v[10] = "\0\1\0\1\0\1\0\1\0\1";
  char w[10] = "\1\0\1\0\1\0\1\0\1\0";

  vxor(v, v, w, 10);
  assert(v[0] == 1);
  assert(v[1] == 1);

  vxor(v, v, w, 10);
  assert(v[0] == 0);
  vxor(v, v, v, 10);

  for (i=0; i!=10; i++)
    assert(v[i] == 0);

}
int main(int argc, char **argv)
{
  test_is_vzero();
  test_vxor();

  return 0;
}

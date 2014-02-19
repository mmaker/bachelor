/**
 * \file qstrings.c
 *
 * \brief Extend stdlib support with some common functions used in questions.
 *
 */
#include <stddef.h>

#include "qa/questions/qstrings.h"


/**
 * \brief xor operations among vectors.
 *
 * Compute the xor operation for len bytes, between v and w, and places the result in u.
 * Note: u can be any of v, w.
 */
void
vxor(void *void_u, const void *void_v, const void *void_w, size_t len)
{
  char unsigned *u = (char unsigned *) void_u;
  char unsigned *v = (char unsigned *) void_v;
  char unsigned *w = (char unsigned *) void_w;

  while (len--)
    *(u++) = *(v++) ^ *(w++);
}


/**
 * \brief Check v the first len bits of v are filled with zeroes
 *
 * \return true if the first len bits of v are zero, false otherwise.
 */
int
is_vzero(const void *v, size_t len)
{
  char unsigned *s = (char unsigned *) v;
  while (len--)
    if (*(s++)) return 0;
  return 1;
}

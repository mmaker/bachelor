/**
 * \file qstrings.c
 *
 * \brief Extend stdlib support with some common functions used in questions.
 *
 */
#include "qa/questions/qstrings.h"


/**
 * \brief Check v the first len bits of v are filled with zeroes
 *
 * \return true if the first len bits of v are zero, false otherwise.
 */
int is_vzero(const void *v, size_t len)
{
  char unsigned *s = (char unsigned *) v;
  while (len--)
    if (*(s++)) return 0;
  return 1;
}

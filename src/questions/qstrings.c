/**
 * \file qstrings.c
 *
 * \brief Extend stdlib support with some common functions used in questions.
 *
 */
#include <stddef.h>
#include <string.h>

#include <openssl/asn1.h>

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
 * \brief swap two vectors.
 *
 *
 *
 */
void
vswap(void *void_a, void *void_b, size_t len)
{
  char unsigned *a = (char unsigned *) void_a;
  char unsigned *b = (char unsigned *) void_b;
  char unsigned c;

  for (; len--; a++, b++) {
    c = *a;
    *a = *b; *b = c;
  }
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


int
ASN1_TIME_str(char *dest, const ASN1_TIME *tm)
{
  char *v;
  int gmt=0;
  int i;
  int y=0,M=0,d=0,h=0,m=0,s=0;
  char *f = NULL;
  int f_len = 0;

  i = tm->length;
  v = (char *)tm->data;

  if (tm->type == V_ASN1_GENERALIZEDTIME) {
    if (i < 12) goto err;
    for (i=0; i<12; i++)
      if ((v[i] > '9') || (v[i] < '0')) goto err;

    if (v[i-1] == 'Z') gmt = 1;
    y = (v[0]-'0')*1000 + (v[1]-'0')*100 + (v[2]-'0')*10 + (v[3]-'0');
    M = (v[4]-'0')*10 + (v[5]-'0');
    if ((M > 12) || (M < 1)) goto err;
    d = (v[6]-'0')*10 + (v[7]-'0');
    h = (v[8]-'0')*10 + (v[9]-'0');
    m =  (v[10]-'0')*10 + (v[11]-'0');
    if (tm->length >= 14 &&
        (v[12] >= '0') && (v[12] <= '9') &&
        (v[13] >= '0') && (v[13] <= '9')) {
      s =  (v[12]-'0')*10 + (v[13]-'0');
      /* Check for fractions of seconds. */
      if (tm->length >= 15 && v[14] == '.') {
      int l = tm->length;
      f = &v[14];	/* The decimal point. */
      for (f_len = 1;
           14 + f_len < l && f[f_len] >= '0' && f[f_len] <= '9';
           f_len++);
      }
    }
  }
  else if (tm->type == V_ASN1_UTCTIME) {
    if (i < 10) goto err;
    for (i=0; i<10; i++)
      if ((v[i] > '9') || (v[i] < '0')) goto err;

    y = (v[0]-'0')*10+(v[1]-'0');
    if (y < 50) y+=100;
    y += 1900;
    M = (v[2]-'0')*10+(v[3]-'0');
    if ((M > 12) || (M < 1)) goto err;
    d = (v[4]-'0')*10+(v[5]-'0');
    h = (v[6]-'0')*10+(v[7]-'0');
    m =  (v[8]-'0')*10+(v[9]-'0');
    if (tm->length >=12 &&
        (v[10] >= '0') && (v[10] <= '9') &&
        (v[11] >= '0') && (v[11] <= '9'))
      s =  (v[10]-'0')*10+(v[11]-'0');

  }
  if (sprintf(dest,"%04d-%02d-%02d %02d:%02d:%02d%.*s %s",
              y, M, d, h, m, s, f_len, f, (gmt)?" GMT":"") > 0)
    return 1;
 err:
  strcpy(dest, "1970-01-01");
  return 0;
}

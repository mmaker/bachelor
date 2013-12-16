/**
 * \file wiener.c
 * \brief An implementation of Wiener's Attack using bignums.
 *
 * Wiener's atttack states that:
 * given N = pq the public modulus, the couple e, d . ed ≡ 1 (mod φ(N))
 * respectively the private and public exponent,
 * given p < q < 2p and d < ⅓ ⁴√N,
 * one can efficently recover d knowing only <N, e>.
 *
 */
#include <math.h>
#include <stdlib.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "qa/questions/questions.h"
#include "qa/questions/qarith.h"
#include "qa/questions/qwiener.h"


/*
 *  Weiner Attack Implementation
 */
static RSA*
wiener_question_ask_rsa(const RSA *rsa)
{
  /* key data */
  RSA *ret = NULL;
  BIGNUM *n, *e, *d, *phi;
  BIGNUM *p, *q;
  /* continued fractions coefficient, and mod */
  cf_t* cf;
  bigfraction_t *it;
  size_t  i;
  BIGNUM *t, *tmp, *rem;
  /* equation coefficients */
  BIGNUM *b2, *delta;
  BN_CTX *ctx;
  int bits;

  phi = BN_new();
  tmp = BN_new();
  rem = BN_new();
  n = rsa->n;
  e = rsa->e;
  b2 = BN_new();
  delta = BN_new();

  /*
   * Generate the continued fractions approximating e/N
   */
  bits = BN_num_bits(n);
  cf = cf_init(NULL, e, n);
  ctx = cf->ctx;
  for (i=0, it = cf_next(cf);
       // XXX. how many keys shall I test?
       i!=bits && it;
       i++, it = cf_next(cf)) {
    t = it->h;
    d = it->k;
    /*
     * Recovering φ(N) = (ed - 1) / t
     * TEST1: obviously the couple {t, d} is correct → (ed-1) | t
     */
    BN_mul(phi, e, d, cf->ctx);
    BN_usub(tmp, phi, BN_value_one());
    BN_div(phi, rem, tmp, t, cf->ctx);
    if (!BN_is_zero(rem)) continue;
    // XXX. check, is it possible to fall here, assuming N, e are valid?
    if (BN_is_odd(phi) && BN_cmp(n, phi) == 1)   continue;
    /*
     * Recovering p, q
     * Solving the equation
     *  x² + [N-φ(N)+1]x + N = 0
     * which, after a few passages, boils down to:
     *  x² + (p+q)x + (pq) = 0
     *
     * TEST2: φ(N) is correct → the two roots of x are integers
     */
    BN_usub(b2, n, phi);
    BN_uadd(b2, b2, BN_value_one());
    BN_rshift(b2, b2, 1);
    if (BN_is_zero(b2)) continue;
    /* delta */
    BN_sqr(tmp, b2, ctx);
    BN_usub(delta, tmp, n);
    if (!BN_sqrtmod(tmp, rem, delta, ctx)) continue;
    /* key found :) */
    ret = RSA_new();
    ret->n = rsa->n;
    ret->e = rsa->e;
    ret->p = p = BN_new();
    ret->q = q = BN_new();
    BN_usub(p, b2, tmp);
    BN_uadd(q, b2, tmp);
    break;
  }

  cf_free(cf);
  BN_free(rem);
  BN_free(tmp);
  BN_free(b2);
  BN_free(delta);
  BN_free(phi);

  return ret;
}



qa_question_t WienerQuestion = {
  .name = "wiener",
  .pretty_name = "Wiener's Attack",
  .setup = NULL,
  .teardown = NULL,
  .test = NULL,
  .ask_rsa = wiener_question_ask_rsa,
  .ask_crt = NULL,
};

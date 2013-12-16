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


cf_t* cf_new(void)
{
  cf_t *f;

  f = (cf_t *) malloc(sizeof(cf_t));

  size_t i;

  for (i=0; i!=3; i++) {
    f->fs[i].h = BN_new();
    f->fs[i].k = BN_new();
  }
  f->a = BN_new();
  f->x.h = BN_new();
  f->x.k = BN_new();

  f->ctx = BN_CTX_new();

  return f;
}

void cf_free(cf_t* f)
{
  size_t i;

  for (i=0; i!=3; i++) {
    BN_free(f->fs[i].h);
    BN_free(f->fs[i].k);
  }
  BN_free(f->a);
  BN_free(f->x.h);
  BN_free(f->x.k);

  free(f);
}


/**
 * \brief Initialized a continued fraction.
 *
 * A continued fraction for a floating number x can be expressed as a series
 *  <a₀; a₁, a₂…, aₙ>
 * such that
 * <pre>
 *
 *                1
 *  x = a₀ + ⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽
 *                    1
 *           a₁ + ⎽⎽⎽⎽⎽⎽⎽⎽⎽
 *                 a₂ + …
 *
 * </pre>
 * , where for each i < n, there exists an approximation hᵢ / kᵢ.
 * By definition,
 *   a₋₁ = 0
 *   h₋₁ = 1    h₋₂ = 0
 *   k₋₁ = 0    k₋₂ = 1
 *
 * \param f     A continued fraction structure. If f is NULL, a new one is
 *              allocated.
 * \param num   Numerator to be used as initial numerator for the fraction to be
 *              approximated.
 * \param den   Denominator to be used as denominator for the fraction to be
 *              approximated.
 *
 * \return the continued fraction fiven as input.
 */
cf_t* cf_init(cf_t* f, BIGNUM* num, BIGNUM* den)
{
  if (!f) f = cf_new();

  BN_zero(f->fs[0].h);
  BN_one(f->fs[0].k);

  BN_one(f->fs[1].h);
  BN_zero(f->fs[1].k);

  f->i = 2;
  if (!BN_copy(f->x.h, num)) return NULL;
  if (!BN_copy(f->x.k, den)) return NULL;

  return f;
}


/**
 * \brief Produces the next fraction.
 *
 * Each new approximation hᵢ/kᵢ is defined rec ursively as:
 *   hᵢ = aᵢhᵢ₋₁ + hᵢ₋₂
 *   kᵢ = aᵢkᵢ₋₁ + kᵢ₋₂
 * Meanwhile each new aᵢ is simply the integer part of x.
 *
 *
 * \param f   The continued fraction.
 * \return NULL if the previous fraction approximates at its best the number,
 *         a pointer to the next fraction in the series othw.
 */
bigfraction_t* cf_next(cf_t *f)
{
  bigfraction_t *ith_fs = &f->fs[f->i];
  BIGNUM* rem = BN_new();

  if (BN_is_zero(f->x.h)) return NULL;
  BN_div(f->a, rem, f->x.h, f->x.k, f->ctx);

  /* computing hᵢ */
  BN_mul(f->fs[f->i].h , f->a, f->fs[(f->i-1+3) % 3].h, f->ctx);
  BN_uadd(f->fs[f->i].h, f->fs[f->i].h, f->fs[(f->i-2+3) % 3].h);
  /* computing kᵢ */
  BN_mul(f->fs[f->i].k , f->a, f->fs[(f->i-1+3) % 3].k, f->ctx);
  BN_uadd(f->fs[f->i].k, f->fs[f->i].k, f->fs[(f->i-2+3) % 3].k);

  f->i = (f->i + 1) % 3;
  /* update x. */
  BN_copy(f->x.h, f->x.k);
  BN_copy(f->x.k, rem);

  return ith_fs;
}


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

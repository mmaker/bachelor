/**
 * \file qarith.c
 * \brief Random Algebraic utilities with BIGNUMs.
 *
 */
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "qa/questions/qarith.h"

const BIGNUM *BN_value_two(void)
{
  static const BN_ULONG data_two = 2L;
  static const BIGNUM const_two = {
    (BN_ULONG *) &data_two,
    1,
    1,
    0,
    BN_FLG_STATIC_DATA
  };

  return &const_two;
}

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

/**
 * \brief Square Root for bignums.
 *
 * An implementation of Dijkstra's Square Root Algorithm.
 * A Discipline of Programming, page 61 - Fifth Exercise.
 *
 * \return true if rem is equal to zero, false otherwise.
 */
int BN_sqrtmod(BIGNUM* dv, BIGNUM* rem, BIGNUM* a, BN_CTX* ctx)
{
  BIGNUM *shift;
  BIGNUM *adj;

  shift = BN_new();
  adj = BN_new();
  BN_zero(dv);
  BN_copy(rem, a);

  /* hacking into internal sequence to skip some cycles. */
  /* for  (BN_one(shift);     original */
  for (bn_wexpand(shift, a->top+1), shift->top=a->top, shift->d[shift->top-1] = 1;
       BN_ucmp(shift, rem) != 1;
       /* BN_rshift(shift, shift, 2); */
       BN_lshift1(shift, shift), BN_lshift1(shift, shift));


  while (!BN_is_one(shift)) {
    /* BN_rshift(shift, shift, 2); */
    BN_rshift1(shift, shift);
    BN_rshift1(shift, shift);

    BN_uadd(adj, dv, shift);
    BN_rshift1(dv, dv);
    if (BN_ucmp(rem, adj) != -1) {
      BN_uadd(dv, dv, shift);
      BN_usub(rem, rem, adj);
    }
  }

  BN_free(shift);
  BN_free(adj);
  return BN_is_zero(rem);
}


RSA* qa_RSA_recover(const RSA *rsapub,
                    const BIGNUM *p,
                    BN_CTX *ctx)
{
  static const char *errmsg = "[!] Incorrect vaues for RSA recovery\n";
  RSA *rsapriv = NULL;
  BIGNUM *p1 = BN_new();
  BIGNUM *q1 = BN_new();
  BIGNUM *phi = BN_new();
  BIGNUM *n = BN_new();

  /* guard for most common errors */
  if (BN_is_zero(rsapub->n) ||
      !BN_is_odd(rsapub->n) ||
      BN_is_zero(p) ||
      !BN_cmp(rsapub->n, p) ||
      !BN_cmp(p, BN_value_one())) {
    fprintf(stderr, errmsg);
    goto end;
  }


  rsapriv = RSA_new();
  rsapriv->p = BN_dup(p);
  rsapriv->q = BN_new();
  BN_div(rsapriv->q, NULL, rsapub->n, rsapriv->p, ctx);
  BN_mul(n, rsapriv->p, rsapriv->q, ctx);
  if (BN_cmp(n, rsapub->n)) {
    fprintf(stderr, errmsg);
    BN_free(rsapriv->p);
    BN_free(rsapriv->q);
    RSA_free(rsapriv);
    rsapriv = NULL;
    goto end;
  }

  rsapriv->n = BN_dup(rsapub->n);
  /* retrieve phi */
  BN_sub(p1, rsapriv->p, BN_value_one());
  BN_sub(q1, rsapriv->q, BN_value_one());
  BN_mul(phi, p1, q1, ctx);
  /* retrieve the private exponent */
  rsapriv->e = BN_dup(rsapub->e);
  rsapriv->d = BN_new();
  BN_mod_inverse(rsapriv->d, rsapriv->e, phi, ctx);
  /* some other openssl shit */
  BN_mod(rsapriv->dmq1, rsapriv->d, q1, ctx);
  BN_mod(rsapriv->dmp1, rsapriv->d, p1, ctx);
  BN_mod_inverse(rsapriv->iqmp, rsapriv->q, rsapriv->p, ctx);

 end:
  BN_free(n);
  BN_free(q1);
  BN_free(p1);
  BN_free(phi);
  return rsapriv;
}

inline BIGNUM *BN_min(BIGNUM *a, BIGNUM *b)
{
  return (BN_cmp(a, b) < 0) ? a : b;
}

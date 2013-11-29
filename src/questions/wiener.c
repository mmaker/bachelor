/**
 * \file wiener.c
 *
 */
#include <math.h>
#include <stdlib.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "questions.h"
#include "qwiener.h"


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
  if (!BN_mul(f->fs[f->i].h , f->a, f->fs[(f->i-1+3) % 3].h, f->ctx)) goto oh_fuck;
  if (!BN_add(f->fs[f->i].h, f->fs[f->i].h, f->fs[(f->i-2+3) % 3].h)) goto oh_fuck;
  /* computing kᵢ */
  if (!BN_mul(f->fs[f->i].k , f->a, f->fs[(f->i-1+3) % 3].k, f->ctx)) goto oh_fuck;
  if (!BN_add(f->fs[f->i].k, f->fs[f->i].k, f->fs[(f->i-2+3) % 3].k)) goto oh_fuck;

  f->i = (f->i + 1) % 3;
  /* update x. */
  if (!BN_copy(f->x.h, f->x.k)) goto oh_fuck;
  if (!BN_copy(f->x.k, rem))    goto oh_fuck;

  return ith_fs;

 oh_fuck:
  printf("of fuck!\n");
  exit(EXIT_FAILURE);
}


int BN_sqrtmod(BIGNUM* dv, BIGNUM* rem, BIGNUM* a, BN_CTX* ctx)
{
  char *abn2dec, *bbn2dec;
  int g[100];
  long al, bl;
  long x = 0, r = 0;
  int i, j;
  int d;
  long y, yn;

  abn2dec = BN_bn2dec(a);
  sscanf(abn2dec, "%ld", &al);

  r = 0;
  x = 0;
  for (i=0; al > 0; i++) {
    g[i] = al%100;
    al /= 100;
  }

  for (j=i-1; j>=0; j--) {
    r = r*100 + g[j];
    y = 0;
    for (d=1; d!=10; d++) {
      yn = d*(20*x + d);
      if (yn <= r) y = yn; else break;
    }
    r -= y;
    x = 10*x + d -1;
  }

  sprintf(abn2dec, "%ld", r);
  BN_dec2bn(&rem, abn2dec);
  sprintf(abn2dec, "%ld", x);
  BN_dec2bn(&dv, abn2dec);


  OPENSSL_free(abn2dec);

  return BN_is_zero(rem);
}


/*
 *  Weiner Attack Implementation
 */

int wiener_question_setup(void) { return 0; }

int wiener_question_teardown(void) { return 0; }

int wiener_question_test(X509* cert) { return 1; }


int wiener_question_ask(X509* cert)
{
  RSA *rsa;
  BIGNUM *n, *e, *d, *phi;
  BIGNUM *t, *tmp, *rem;
  cf_t* cf;
  bigfraction_t *it;
  size_t  i;

  phi = BN_new();
  tmp = BN_new();
  rem = BN_new();
  rsa = X509_get_pubkey(cert)->pkey.rsa;
  n = rsa->n;
  e = rsa->e;

  cf = cf_init(NULL, n, e);

  for (i=0, it = cf_next(cf);
       i!=100 && it;
       i++, it = cf_next(cf)) {
    t = it->h;
    d = it->k;
    BN_mul(phi, e, d, cf->ctx);
    BN_sub(tmp, phi, BN_value_one());
    BN_div(phi, rem, tmp, t, cf->ctx);

    /* test 1: there shall be no rem */
    if (!BN_is_zero(rem)) continue;

    printf("Found? ");
    BN_print_fp(stdout, e);
    printf(" ");
    BN_print_fp(stdout, d);
    printf(" ");
    BN_print_fp(stdout, phi);
  }

  cf_free(cf);
  return 0;
}



qa_question_t WienerQuestion = {
  .name = "Wiener",
  .setup = wiener_question_setup,
  .teardown = wiener_question_teardown,
  .test = wiener_question_test,
  .ask = wiener_question_ask
};

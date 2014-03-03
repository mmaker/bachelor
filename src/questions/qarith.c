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
  for  (BN_one(shift);    /*  original  */
  /* for (bn_wexpand(shift, a->top+1), shift->top=a->top, shift->d[shift->top-1] = 1; */
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


#define INCORRECT_VALUES_RSA_RECOVERY \
   "[!] Incorrect vaues for RSA recovery\n"

RSA* qa_RSA_recover(const RSA *rsapub,
                    const BIGNUM *p,
                    BN_CTX *ctx)
{
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
    fprintf(stderr, INCORRECT_VALUES_RSA_RECOVERY);
    goto end;
  }


  rsapriv = RSA_new();
  rsapriv->p = BN_dup(p);
  rsapriv->q = BN_new();
  BN_div(rsapriv->q, NULL, rsapub->n, rsapriv->p, ctx);
  BN_mul(n, rsapriv->p, rsapriv->q, ctx);
  if (BN_cmp(n, rsapub->n)) {
    fprintf(stderr, INCORRECT_VALUES_RSA_RECOVERY);
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
  rsapriv->dmq1 = BN_new();
  BN_mod(rsapriv->dmq1, rsapriv->d, q1, ctx);
  rsapriv->dmp1 = BN_new();
  BN_mod(rsapriv->dmp1, rsapriv->d, p1, ctx);
  rsapriv->iqmp = BN_new();
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

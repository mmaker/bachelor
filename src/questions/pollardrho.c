/**
 * \file pollardrho.c
 *
 * \brief Pollard's ρ factorization method.
 *
 * This file contains two implementations of the pollard's ρ algorithm, used in
 * order to attempt a factorization of N.
 */

#include <openssl/rsa.h>

#include <qa/questions/qarith.h>
#include <qa/questions/questions.h>


static inline void f(BIGNUM *y, BIGNUM *n, BN_CTX *ctx)
{
  /* y ← f(y) = y² + 1 (mod N) */
  BN_mod_sqr(y, y, n, ctx);
  BN_uiadd1(y);
}

/*
 * \brief Pollard-Brent variant of the ρ factorization.
 *
 * This algorithm shall be around 24% fasted discovering the cyclic part.
 * Moreover, gcd is computed on the accoumulated value q, which makes it even
 * just awesome.
 */
static RSA*
pollardbrent_question_ask_rsa(const RSA *rsa)
{
  RSA *ret = NULL;
  BIGNUM
    *x = BN_new(),
    *y = BN_new(),
    *ys = BN_new(),
    *r = BN_new(),
    *q = BN_new(),
    *g = BN_new(),
    *i = BN_new(),
    *j = BN_new(),
    *m = BN_new(),
    *k = BN_new(),
    *diff = BN_new();
  BN_CTX *ctx = BN_CTX_new();


  BN_one(r);
  BN_one(q);
  BN_one(g);
  BN_dec2bn(&m, "100");
  BN_pseudo_rand_range(y, rsa->n);

  while (BN_is_one(g)) {
    BN_copy(x, y);
    for (BN_copy(i, r);
         !BN_is_zero(i);
         BN_sub(i, i, BN_value_one()))
      f(y, rsa->n, ctx);

    for (BN_zero(k);
         BN_cmp(k, r) < 1 && BN_is_one(g);
         BN_add(k, k, m)) {
      BN_copy(ys, y);
      BN_sub(diff, r, k);
      for (BN_copy(j, BN_min(m, diff));
           !BN_is_zero(j);
           BN_sub(j, j, BN_value_one())) {
        f(y, rsa->n, ctx);
        /* q ← q * |x-y| */
        BN_sub(diff, x, y);
        BN_abs(diff);
        BN_mod_mul(q, q, diff, rsa->n, ctx);
      }
      BN_gcd(g, q, rsa->n, ctx);
    }
    BN_lshift1(r,r);
  }

  if (!BN_cmp(g, rsa->n)) do {
      f(ys, rsa->n, ctx);
      BN_sub(diff, x, ys);
      BN_abs(diff);
      BN_gcd(g, diff, rsa->n, ctx);
    } while (BN_is_one(g));

  if (BN_cmp(g, rsa->n))
    ret = qa_RSA_recover(rsa, g, ctx);


  BN_free(diff);
  BN_free(x);
  BN_free(k);
  BN_free(m);
  BN_free(y);
  BN_free(ys);
  BN_free(r);
  BN_free(q);
  BN_free(g);
  BN_free(i);

  return ret;
}

/**
 * \brief Pollard's ρ factorization.
 *
 * This is the naïve implementation of pollard's ρ factorization employing
 * Floyd's cycle finding algorithm.
 *
 */
static RSA*
pollardrho_question_ask_rsa(const RSA *rsa)
{
  RSA *ret = NULL;
  BIGNUM
    *x = NULL,
    *y = NULL;
  BIGNUM *n;
  BIGNUM *tmp;
  BIGNUM *gcd;
  BN_CTX *ctx;

  ctx = BN_CTX_new();
  gcd = BN_new();
  x = BN_new();
  y = BN_new();
  tmp = BN_new();
  n = rsa->n;

  /* initialization */
  BN_one(gcd);
  BN_pseudo_rand(x, 512, 0, 0);
  BN_copy(y, x);


  while (BN_is_one(gcd)) {
    /* x ← x² + 1 (mod N) */
    BN_mod_sqr(x, x, n, ctx);
    BN_uiadd1(x);
    /* y ← y⁴ + 2y² + 2 (mod N) */
    BN_mod_sqr(tmp, y, n, ctx);
    BN_mod_sqr(y, tmp, n, ctx);
    BN_lshift1(tmp, tmp);
    BN_mod_add(y, y, tmp, n, ctx);
    BN_mod_add(y, y, BN_value_two(), n, ctx);
    /* gcd(|x-y|, N) */
    BN_mod_sub(tmp, x, y, n, ctx);
    BN_gcd(gcd, tmp, n, ctx);
  }

  if (BN_ucmp(gcd, n) != 0)
    ret = qa_RSA_recover(rsa, gcd, ctx);

  BN_free(tmp);
  BN_free(x);
  BN_free(y);
  BN_free(gcd);
  return ret;
}

qa_question_t PollardRhoQuestion = {
  .name = "pollardrho",
  .pretty_name = "Pollard's ρ factorization",
  .ask_rsa = pollardrho_question_ask_rsa
};


qa_question_t PollardBrentRhoQuestion = {
  .name = "pollard-brent",
  .pretty_name = "Pollard-Brent's ρ factorization",
  .ask_rsa = pollardbrent_question_ask_rsa
};

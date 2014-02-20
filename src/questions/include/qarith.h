#ifndef _QA_ARITH_H_
#define _QA_ARITH_H


/* shortcut macros. */
#define BN_uiadd1(a) BN_uadd(a, a, BN_value_one())

/**
 * Fractions made of bignums.
 */
typedef struct bigfraction {
  BIGNUM* h;   /**< numerator */
  BIGNUM* k;   /**< denominator */
} bigfraction_t;


typedef struct cf {
  bigfraction_t fs[3];
  short i;
  bigfraction_t x;
  BIGNUM* a;
  BN_CTX* ctx;
} cf_t;


/* continued fractions utilities. */
cf_t* cf_new(void);

cf_t* cf_init(cf_t *f, BIGNUM *num, BIGNUM *b);

void cf_free(cf_t* f);

bigfraction_t* cf_next(cf_t *f);


/* square root calculation */
int BN_sqrtmod(BIGNUM* dv, BIGNUM* rem, BIGNUM* a, BN_CTX* ctx);

RSA* qa_RSA_recover(const RSA *rsapub, const BIGNUM *p, BN_CTX *ctx);
#endif /* _QA_ARITH_H_ */

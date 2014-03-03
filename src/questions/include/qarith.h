#ifndef _QA_ARITH_H_
#define _QA_ARITH_H


/* shortcut macros. */
#define BN_uiadd1(a) BN_uadd(a, a, BN_value_one())

#define BN_abs(a)  BN_set_negative(a, 0)

BIGNUM* BN_min(BIGNUM *a, BIGNUM *b);

/* square root calculation */
int BN_sqrtmod(BIGNUM* dv, BIGNUM* rem, BIGNUM* a, BN_CTX* ctx);

RSA* qa_RSA_recover(const RSA *rsapub, const BIGNUM *p, BN_CTX *ctx);

const BIGNUM *BN_value_two(void);

#endif /* _QA_ARITH_H_ */

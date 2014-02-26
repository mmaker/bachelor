#ifndef _QA_WILLIAMS_H_
#define _QA_WILLIAMS_H_

extern struct qa_question WilliamsQuestion;

void lucas(BIGNUM *v, BIGNUM *w,
           BIGNUM *h, BIGNUM *tau,
           BIGNUM *n, BN_CTX *ctx);


#endif /* _QA_WILLIAMS_H_ */

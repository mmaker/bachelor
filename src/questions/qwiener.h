#ifndef _QA_WIENER_H_
#define _QA_WIENER_H

#include <stdlib.h>
#include <openssl/bn.h>

/**
 * Fractions made of bignums.
 */
typedef struct bigfraction {
  BIGNUM* h;
  BIGNUM* k;
} bigfraction_t;

typedef struct cf {
  bigfraction_t fs[3];
  short i;
  bigfraction_t x;
  BIGNUM* a;
  BN_CTX* ctx;
} cf_t;

cf_t* cf_new(void);
cf_t* cf_init(cf_t *f, BIGNUM *num, BIGNUM *b);
bigfraction_t* cf_next(cf_t *f);

extern struct qa_question WienerQuestion;
#endif

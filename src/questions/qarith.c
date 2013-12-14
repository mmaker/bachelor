#include <openssl/bn.h>

#include "qa/questions/qarith.h"

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

/**
 * \file gen.c
 *
 * Generate a fake RSA certificate file, given as input e, d, p, q.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>


void usage(void)
{
  static const char* help_message = "%s usage: %s"
    " <pub key> <priv key> <p> <q>"
    "\n";
  fprintf(stderr, help_message, program_invocation_short_name,
          program_invocation_name);
}

int main(int argc, char **argv)
{
  BN_CTX* ctx;
  BIGNUM* p1, *q1;
  RSA* rsa;

  rsa = RSA_new();
  p1 = BN_new();
  q1 = BN_new();
  ctx = BN_CTX_new();
  rsa->n = BN_new();
  rsa->iqmp = BN_new();
  rsa->dmp1 = BN_new();
  rsa->dmq1 = BN_new();

  if (argc < 4+1) {
    usage();
    return EXIT_FAILURE;
  }

  BN_dec2bn(&rsa->e, argv[1]);
  BN_dec2bn(&rsa->d, argv[2]);
  BN_dec2bn(&rsa->p, argv[3]);
  BN_dec2bn(&rsa->q, argv[4]);
  BN_mul(rsa->n, rsa->p, rsa->q, ctx);
  BN_sub(p1, rsa->p, BN_value_one());
  BN_sub(q1, rsa->q, BN_value_one());
  BN_mod(rsa->dmq1, rsa->d, q1, ctx);
  BN_mod(rsa->dmp1, rsa->d, p1, ctx);
  BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);
  PEM_write_RSAPrivateKey(stdout, rsa, NULL, NULL, 0, NULL, NULL);


  BN_CTX_free(ctx);
  BN_free(q1);
  BN_free(p1);
  RSA_free(rsa);

  return 0;
}

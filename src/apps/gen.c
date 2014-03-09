/**
 * \file gen.c
 *
 * Generate a fake RSA certificate file, given as input e, d, p, q.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>

static void
usage(int ret)
{
  static const char* help_message = "%s usage: \n"
    "%s pub [-n MODULUS | -p PRIME -q PRIME] -e PUBLIC_EXPONENT\n"
    "%s priv -p PRIME -q PRIME -e PUBLIC_EXPONENT -d PRIVATE_EXPONENT\n";
  fprintf(stderr, help_message, program_invocation_short_name,
          program_invocation_name, program_invocation_name);

  exit(ret);
}


static int
pubkey_generation(RSA* rsa)
{
  BN_CTX *ctx = BN_CTX_new();
  EVP_PKEY *pkey = EVP_PKEY_new();
  int ret = EXIT_SUCCESS;

  /* if not specified, use the default rsa public exponent */
  if (!rsa->e)
    BN_dec2bn(&rsa->e, "65537");

  if (!rsa->n && !rsa->p) {
    rsa->p = BN_new();
    BN_generate_prime(rsa->p, 512, 0, NULL, NULL, NULL, NULL);
  }

  if (!rsa->n && !rsa->q) {
    rsa->q = BN_new();
    BN_generate_prime(rsa->q, 512, 0, NULL, NULL, NULL, NULL);
  }

  if (!rsa->n) {
    rsa->n = BN_new();
    BN_mul(rsa->n, rsa->p, rsa->q, ctx);
  }

  assert(BN_is_odd(rsa->n));

  //  PEM_write_RSAPublicKey(stdout, rsa);
  if (!EVP_PKEY_set1_RSA(pkey, rsa)) {
    ret = EXIT_FAILURE;
    goto end;
  }
  PEM_write_PUBKEY(stdout, pkey);

 end:
  RSA_free(rsa);
  EVP_PKEY_free(pkey);
  BN_CTX_free(ctx);

  return ret;
}

static int
privkey_generation(RSA *rsa)
{
  BIGNUM *p1, *q1;
  BN_CTX *ctx = BN_CTX_new();

  if (!(rsa->p && rsa->q && rsa->e && rsa->d)) {
    fprintf(stderr, "Not enough parameter for the private key generation!\n");
    return EXIT_FAILURE;
  }

  p1 = BN_new();
  q1 = BN_new();
  rsa->n = BN_new();
  rsa->iqmp = BN_new();
  rsa->dmp1 = BN_new();
  rsa->dmq1 = BN_new();

  /* generating RSA key */
  BN_mul(rsa->n, rsa->p, rsa->q, ctx);
  BN_sub(p1, rsa->p, BN_value_one());
  BN_sub(q1, rsa->q, BN_value_one());
  BN_mod(rsa->dmq1, rsa->d, q1, ctx);
  BN_mod(rsa->dmp1, rsa->d, p1, ctx);
  BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);
  PEM_write_RSAPrivateKey(stdout, rsa, NULL, NULL, 0, NULL, NULL);

  BN_CTX_free(ctx);
  return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
  int opt;
  RSA *rsa = RSA_new();

  rsa->n = rsa->e = rsa->p = rsa->q = NULL;

  if (argc < 2) usage(EXIT_FAILURE);

  while ((opt = getopt(argc-1, argv+1, "d:e:N:n:p:q:")) != -1)  {
    switch (opt) {
    case 'N':
    case 'n':
      if (!BN_dec2bn(&rsa->n, optarg)) usage(EXIT_FAILURE);
      break;
    case 'd':
      if (!BN_dec2bn(&rsa->d, optarg)) usage(EXIT_FAILURE);
      break;
    case 'e':
      if (!BN_dec2bn(&rsa->e, optarg)) usage(EXIT_FAILURE);
      break;
    case 'p':
      if (!BN_dec2bn(&rsa->p, optarg)) usage(EXIT_FAILURE);
      break;
    case 'q':
      if (!BN_dec2bn(&rsa->q, optarg)) usage(EXIT_FAILURE);
      break;
    default:
      usage(EXIT_FAILURE);
    }
  }

  SSL_library_init();

  if (!strcmp(argv[1], "pub"))
    return pubkey_generation(rsa);
  else if (!strcmp(argv[1], "priv"))
    return privkey_generation(rsa);
  else
    usage(EXIT_FAILURE);
}

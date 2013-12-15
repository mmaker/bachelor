/**
 * \file gen.c
 *
 * Generate a fake RSA certificate file, given as input e, d, p, q.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>

static void
usage(int ret)
{
  static const char* help_message = "%s usage: \n"
    "%s pub [-n MODULUS | -p PRIME -q PRIME] -e PUBLIC_EXPONENT\n"
    "%s priv -p PRIME -q PRIME -e PUBLIC_EXPONENT -d PRIVATE_EXPONENT\n";
  fprintf(stderr, help_message, program_invocation_short_name,
          program_invocation_name);

  exit(ret);
}


static int
pubkey_generation(RSA* rsa)
{
  BN_CTX *ctx = BN_CTX_new();

  /* we need <N, e> to get a valid public key. */
  if (!(rsa->e &&
        (rsa->n ||(rsa->p && rsa->q)))) {
    fprintf(stderr, "Not enough parameter for the public key generation!\n");
    exit(EXIT_FAILURE);
    }

  if (!rsa->n)
    BN_mul(rsa->n, rsa->p, rsa->q, ctx);

  PEM_write_RSAPublicKey(stdout, rsa);

  BN_CTX_free(ctx);
  return EXIT_SUCCESS;
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

  if (argc < 3) usage(EXIT_FAILURE);

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

  if (!strcmp(argv[1], "pub"))
    return pubkey_generation(rsa);
  else if (!strcmp(argv[1], "priv"))
    return privkey_generation(rsa);
  else
    usage(EXIT_FAILURE);

  /* creating public key */
  /*
  EVP_PKEY *pk;
  pk = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pk, rsa);
  */
  /* creating dummy certificate */
  /*
  X509* crt;
  crt = X509_new();
  if (!X509_set_pubkey(crt, pk)) exit(EXIT_FAILURE);
  */
  /* PEM_write_X509(stdout, crt); */
  /*
  X509_free(crt);
  EVP_PKEY_free(pk);
  BN_free(q1);
  BN_free(p1);
  RSA_free(rsa);

  */
  return EXIT_SUCCESS;
}

/**
 * \file stranamore.c
 *
 * \brief Probe for common prime factors among a file of public moduluses.
 */
#include <stdio.h>
#include <stdlib.h>

#include <mpi.h>
#include <openssl/bn.h>

#define EQUAL_BN "equal"
#define PRIME    "prime"

int next_mod(BIGNUM **n, FILE *fp)
{
  static char buf[1000];

  if (fscanf(fp, "%s", buf) != 1)
    return 0;
  else return BN_hex2bn(n, buf);
}

/**
 * \brief Test for a pair of moduluses having a prime factor in common.
 *
 */
int test(BIGNUM *n, BIGNUM *m)
{
  BIGNUM *g;
  BN_CTX *ctx;
  int ret = 0;

  g = BN_new();
  ctx = BN_CTX_new();

  if (!BN_cmp(n, m)) {
    fprintf(stderr, "%-8s: ", EQUAL_BN);
    BN_print_fp(stderr, n);
    fprintf(stderr, "\n");
    ret = 1;
    goto end;
  }

  BN_gcd(g, n, m, ctx);
  if (!BN_is_one(g)) {
    fprintf(stdout, "%-8s: ", PRIME);
    BN_print_fp(stdout, n);
    fprintf(stdout, "  ");
    BN_print_fp(stdout, m);
    fprintf(stdout, "\n");
    ret = 1;
  }


 end:
  BN_CTX_free(ctx);
  BN_free(g);

  return ret;
}

int main(int argc, char **argv)
{
  FILE *fst, *snd;
  BIGNUM *n, *m;

  n = BN_new();
  m = BN_new();

  MPI_Init(0, NULL);

  if (argc < 2) return EXIT_FAILURE;
  fst = fopen(argv[argc-1], "r");
  if (!fst) return EXIT_FAILURE;
  snd = fopen(argv[argc-1], "r");
  if (!snd) return EXIT_FAILURE;


  while (next_mod(&n, fst)) {
    fseek(snd, ftell(fst), SEEK_SET);
    /* trash first modulus */
    next_mod(&m, snd);
    while (next_mod(&m, snd)) test(n, m);
  }

  BN_free(n);
  BN_free(m);

  MPI_Finalize();
  return 0;

}

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
  static char buf[2048];

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

  if (!BN_cmp(n, m)) return 1;

  g = BN_new();
  ctx = BN_CTX_new();
  BN_gcd(g, n, m, ctx);
  if (!BN_is_one(g)) {
    fprintf(stdout, "%-8s: ", PRIME);
    BN_print_fp(stdout, n);
    fprintf(stdout, "  ");
    BN_print_fp(stdout, m);
    fprintf(stdout, "\n");
    ret = 1;
  }

  BN_CTX_free(ctx);
  BN_free(g);

  return ret;
}

int main(int argc, char **argv)
{
  FILE *fst, *snd;
  BIGNUM *n, *m;
  int i;
  /* long j=0, k=0; */
  int proc, procs;

  MPI_Init(&argc, &argv);
  MPI_Comm_rank(MPI_COMM_WORLD, &proc);
  MPI_Comm_size(MPI_COMM_WORLD, &procs);

  if (argc < 2) return EXIT_FAILURE;
  fst = fopen(argv[argc-1], "r");
  if (!fst) return EXIT_FAILURE;
  snd = fopen(argv[argc-1], "r");
  if (!snd) return EXIT_FAILURE;

  n = BN_new();
  m = BN_new();


  while (next_mod(&n, fst)) {
    fseek(snd, ftell(fst), SEEK_SET);
    /* k++; j=0; */
    /* trash first modulus */
    if (!next_mod(&m, snd)) continue;
    for (i=0; next_mod(&m, snd); i =(i+1) % procs) {
      /* j++; */
      if (i != proc) continue;
      /* if (j % 1000 == 0) fprintf(stdout, "(%5ld, %5ld) lines (and counting..)\n", j, k); */
      test(n, m);
    }
  }

  BN_free(n);
  BN_free(m);
  fclose(fst);
  fclose(snd);

  MPI_Finalize();
  return 0;

}

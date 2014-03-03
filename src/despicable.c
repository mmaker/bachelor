/**
 * \file donnie.c
 * \brief Perform specific factorization attacks on the cluster.
 *
 *
 * For now, just using wiener, expecting a csv file composed of pairs <n, e>.
 */
#include <openssl/rsa.h>
#include <mpi.h>

#include "qa/questions/questions.h"
#include "qa/questions/qwiener.h"

int next_pkey(RSA *pub, FILE *fp)
{
  static char nbuf[2048];
  static char ebuf[10];

  if (fscanf(fp, "%s\t%s", nbuf, ebuf) != 2)
    return 0;
  BN_hex2bn(&pub->n, nbuf);
  BN_hex2bn(&pub->e, ebuf);
  return 1;
}

int main(int argc, char **argv)
{
  FILE *fp;
  RSA *rsa;
  int proc, procs;
  int i;
  QA_library_init();

  MPI_Comm_rank(MPI_COMM_WORLD, &proc);
  MPI_Comm_size(MPI_COMM_WORLD, &procs);

  if (argc < 1) return EXIT_FAILURE;
  if (!(fp = fopen(argv[argc-1], "r"))) return EXIT_FAILURE;

  rsa = RSA_new();
  rsa->n = BN_new();
  rsa->e = BN_new();
  for (i=0; next_pkey(rsa, fp); i = (i+1) % procs) {
    if (i != proc) continue;
    if (run_question(&WienerQuestion, NULL, rsa) == 1) {
      BN_print_fp(stdout, rsa->n);
      fprintf(stdout, "\t broken\n");
    }
  }

  MPI_Finalize();
  return EXIT_SUCCESS;
}

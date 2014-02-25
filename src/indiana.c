/**
 * \file indiana.c
 * \brief Exploring random ssl connections, experimening with the cluster.
 *
 */
#include <stdlib.h>

#include <mpi.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

#include "qa/qa_sock.h"
#include "qa/questions/questions.h"

extern qa_question_t MetadataQuestion;

int main(int argc, char **argv)
{
  int proc, procs;
  long i;
  char *file = "sites.txt";
  FILE *fp;
  char site[128];
  X509 *crt;
  RSA *rsa;

  QA_library_init();

  MPI_Comm_rank(MPI_COMM_WORLD, &proc);
  MPI_Comm_size(MPI_COMM_WORLD, &procs);

  fp = fopen(file, "r");
  if (!fp) return EXIT_FAILURE;

  for (i=0; fscanf(fp, "%s", site) == 1; i = (i+1) % procs) {
    if (i != proc) continue;

    crt = get_remote_cert(site);
    if (!crt) {
      fprintf(stderr, "NO SSL: '%s'\n", site);
      continue;
    }

    rsa = X509_get_pubkey(crt)->pkey.rsa;
    run_question(&MetadataQuestion, crt, rsa);
    X509_free(crt);
  }

  QA_library_del();
  return EXIT_SUCCESS;

}

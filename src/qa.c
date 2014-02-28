/**
 * \file qa.c
 * \brief QA controller and engine.
 *
 * After retrieving a valid configuration from the frontend, this file takes
 * care of running the actual mainloop.
 */
#include "config.h"

#include <assert.h>
#include <error.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_OPENMPI
#include <mpi.h>
#endif

#include <bsd/sys/queue.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "qa/qa.h"
#include "qa/questions/questions.h"
#include "qa/qa_sock.h"

static int qa_dispose(X509 *crt, RSA *rsa);

/**
 * \Handle unexpected error.
 *
 * Function handling fatal errors: exit immediately, reporting eventual errors
 * coming from openssl/bio or the standard errno.
 */
void
qa_abort(const char *reason)
{
  //ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

/**
 * \brief Loads a valid ssl certificate from file.
 *
 * \return NULL in case of error, a X509* structure otherwise.
 */
X509*
get_local_cert(const char *src)
{
  X509 *crt;
  FILE *fp;

  if (!strcmp(src, "-")) fp = stdin;
  else if (!(fp = fopen(src, "r")))
    return NULL;

  crt = PEM_read_X509(fp, NULL, 0, NULL);
  return crt;
}

/**
 * \brief Loads a valid rsa public key from file.
 *
 * \return NULL in case of error, a X509* structure otherwise.
 */
RSA*
get_local_rsa(const char *src)
{
  EVP_PKEY *pkey = NULL;
  FILE *fp;

  if (!strcmp(src, "-")) fp = stdin;
  else if (!(fp = fopen(src, "r")))
    return NULL;

  pkey = PEM_read_PUBKEY(fp, &pkey, NULL, NULL);
  if (pkey == NULL)
    return NULL;
  if (pkey->type != EVP_PKEY_RSA) {
    EVP_PKEY_free(pkey);
    return NULL;
  }
  return pkey->pkey.rsa;
  // rsa = PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
}


/**
 * \brief Given an initial configuration, stuctures the program flow.
 *
 * \param[in] args   Initial configuration given from a frontend.
 */
int
qa_init(const struct qa_conf* conf)
{
  int exitcode;
  X509 *crt = NULL;
  RSA *rsa = NULL;

  /* bind stdout/stderr to a BIO shit to be used externally */
  bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

  QA_library_init();

  if (!conf->attacks) select_all_questions();
  else select_question(conf->attacks);
  if (!questions.lh_first) error(EXIT_FAILURE, 0, "No valid question selected.");

  if (conf->src_type == REMOTE)
    crt = get_remote_cert(conf->src);
  else if (conf->src_type == LOCAL_X509)
    crt = get_local_cert(conf->src);
  else if (conf->src_type == LOCAL_RSA)
    rsa = get_local_rsa(conf->src);
  else
    error(EXIT_FAILURE, 0, "iternal error: unable to determine source type.");
  if (!crt && !rsa)
    error(EXIT_FAILURE, errno, "Unable to open source \"%s\" :", conf->src);

  exitcode = qa_dispose(crt, rsa);
  X509_free(crt);
  return exitcode;
}

static int
qa_dispose(X509 *crt, RSA *rsa)
{
  int exit_code;
  RSA *pub;
  qa_question_t *q;
  EVP_PKEY *pkey;
#ifdef HAVE_OPENMPI
  int proc, procs, i;
#endif

  if (!rsa && crt)  {
    pkey = X509_get_pubkey(crt);
    if (pkey && pkey->type == EVP_PKEY_RSA) pub = pkey->pkey.rsa;
    else {
      fprintf(stderr, "[!] Unsupported certificate\n");
      goto end;
    }
  }
  else pub = rsa;
  printf("[+] Certificate acquired\n");

#ifdef HAVE_OPENMPI
  MPI_Comm_rank(MPI_COMM_WORLD, &proc);
  MPI_Comm_size(MPI_COMM_WORLD, &procs);
  i = 0;
#endif

  LIST_FOREACH(q, &questions, qs) {

#ifdef HAVE_OPENMPI
    if (i++ %  procs != proc) continue;
#endif

    printf( "[-] Running: %s\n", q->pretty_name);
    switch (run_question(q, crt, pub)) {
    case -3:
      fprintf(stderr, "[x] Unexpected error shutting down question %s\n", q->pretty_name);
      exit_code = EXIT_FAILURE;
    case -2:
      fprintf(stderr, "[x] Unexpected error loading question %s\n", q->pretty_name);
      exit_code = EXIT_FAILURE;
      break;
    case -1:
      fprintf(stderr, "[|] Question %s cannot attack the given certificate.\n", q->pretty_name);
      exit_code = EXIT_SUCCESS;
      break;
    case 0 :
      fprintf(stderr, "[♥] Key is resistant to %s\n", q->pretty_name);
      exit_code = EXIT_SUCCESS;
      break;
    default:
      fprintf(stderr, "[\\] Key has been Broken using %s.\n", q->pretty_name);
      exit_code = EXIT_SUCCESS;
      goto end;
    }
  }

end:
  QA_library_del();
  /*
   *  Key seems resistent: exit successfully.
   */
  return exit_code;
}

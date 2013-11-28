#include <assert.h>
#include <error.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "qa.h"
#include "questions.h"
#include "qa_sock.h"

/** BIO wrapper around stdout */
BIO* bio_out;
/** BIO wrapper around srderr */
BIO* bio_err;


void qa_abort(const char *reason)
{
  //ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

X509* get_local_cert(const char *src)
{
  X509* crt;
  FILE* fp;

  if (!strcmp(src, "-")) fp = stdin;
  else if (!(fp = fopen(src, "r")))
    return NULL;

  crt = PEM_read_X509(fp, NULL, 0, NULL);
  return crt;
}

/**
 * \brief Given an initial configuration, stuctures the program flow.
 *
 * \param[in] args   Initial configuration given from a frontend.
 */
int qa_init(const struct qa_conf* conf)
{
  X509 *crt;
  struct qa_question *q;

  /* bind stdout/stderr to a BIO shit to be used externally */
  bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

  /* Initialize SSL Library by registering algorithms. */
  SSL_library_init();


  if (conf->src_type == REMOTE)
    crt = get_remote_cert(conf->src);
  else if (conf->src_type == LOCAL)
    crt = get_local_cert(conf->src);
  else
    error(EXIT_FAILURE, 0, "iternal error: unable to determine source type.");

  if (!crt)
    error(EXIT_FAILURE, errno, "oops");

  register_all_questions();
  for (q=questions.lh_first; q; q = q->qs.le_next) {
    q->setup();
    q->test(crt);
    q->ask(crt);
    q->teardown();
  }

  X509_free(crt);

  return 0;
}

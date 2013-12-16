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

#include "qa/qa.h"
#include "qa/questions/questions.h"
#include "qa/qa_sock.h"

void qa_abort(const char *reason)
{
  //ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

X509* get_local_cert(const char *src)
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
 * \brief Given an initial configuration, stuctures the program flow.
 *
 * \param[in] args   Initial configuration given from a frontend.
 */
int qa_init(const struct qa_conf* conf)
{
  X509 *crt;

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


  if (!conf->attacks) select_all_questions();
  else select_question(conf->attacks);

  if (!questions.lh_first) error(EXIT_FAILURE, 0, "No valid question selected.");

  qa_dispose(crt);

  X509_free(crt);
  return 0;
}

void qa_dispose(X509 *crt)
{
  RSA *rsa;
  qa_question_t *q;

  rsa = X509_get_pubkey(crt)->pkey.rsa;

  printf("[+] Certificate acquired\n");
  for (q=questions.lh_first; q; q = q->qs.le_next) {
    printf( "[-] Running: %s\n", q->pretty_name);
    if (q->setup)    q->setup();
    if (q->test)     q->test(crt);
    if (q->ask_rsa)  q->ask_rsa(rsa);
    if (q->ask_crt)  q->ask_crt(crt);
    if (q->teardown) q->teardown();
  }

}

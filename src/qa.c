#include <assert.h>
#include <error.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <bsd/sys/queue.h>

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
  X509 *crt = NULL;

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
  RSA *pub = X509_get_pubkey(crt)->pkey.rsa;
  RSA *priv;
  qa_question_t *q;

  printf("[+] Certificate acquired\n");
  LIST_FOREACH(q, &questions, qs) {
    printf( "[-] Running: %s\n", q->pretty_name);

    /*
     * Run setup. If it fails, then print an error message and go to the next
     * question.
     */
    if (q->setup && q->setup() <= 0)  {
      fprintf(stderr, "[x] Unexpected error loading question %s\n", q->pretty_name);
      continue;
    }

    /*
     * Run test. If the test is undecidible or either okk, go on. Otherwise,
     * print an error message and go to the next question.
     */
    if (q->test && q->test(crt) < 0) {
      fprintf(stderr, "[|] Question %s cannot attack the given certificate.\n", q->pretty_name);
      continue;
    }

    /*
     * Attempt to attack RSA. If the attack went ok, there's no need to go
     * on. Print out a nice message and then quit.
     */
    if (q->ask_rsa &&
        (priv = q->ask_rsa(pub))) {
      fprintf(stderr, "[\\] Key Broken using %s.\n", q->pretty_name);

    }

    /*
     * Attempt to attack the X509 certificate.
     */
    if (q->ask_crt)  q->ask_crt(crt);

    /*
     * Shut down the given question. If it fails, print an error messae and go
     * on.
     */
    if (q->teardown && q->teardown() <= 0) {
      fprintf(stderr, "[x] Unexpected error shutting down question %s.\n", q->pretty_name);
      continue;
    }
  }

  /*
   *  Key seems resistent: exit with status -1
   */
  exit(-1);
}

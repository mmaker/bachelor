/**
 * \file qa.c
 * \brief QA controller and engine.
 *
 * After retrieving a valid configuration from the frontend, this file takes
 * care of running the actual mainloop.
 */

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
 * /return NULL in case of error, a X509* structure otherwise.
 */
RSA*
get_local_rsa(const char *src)
{
  RSA *rsa = NULL;
  FILE *fp;

  if (!strcmp(src, "-")) fp = stdin;
  else if (!(fp = fopen(src, "r")))
    return NULL;

  rsa = PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
  return rsa;
}

/**
 * \brief Print out a valid RSA Private Key.
 *
 */
static void
print_rsa_private(RSA *rsa)
{
  size_t i;
  char *dec, *hex;
  const struct {
    const char *desc;
    BIGNUM *n;
  } items[5] = {
    {"Public Modulus", rsa->n},
    {"Prime Factor p", rsa->p},
    {"Prime Factor q", rsa->q},
    {"Public Exponent", rsa->e},
    {"Private Exponent", rsa->d},
  };


  assert(rsa); /* && rsa->p && rsa->q && rsa->e); */
  for (i=0; i!=5; i++) {
    if (!items[i].n) continue;
    dec = BN_bn2dec(items[i].n);
    hex = BN_bn2hex(items[i].n);
    fprintf(stdout, "\t%-22s : %-15s (0x%s)\n", items[i].desc, dec, hex);
    OPENSSL_free(dec);
    OPENSSL_free(hex);
  }
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

  /* Initialize SSL Library by registering algorithms. */
  SSL_library_init();

  if (conf->src_type == REMOTE)
    crt = get_remote_cert(conf->src);
  else if (conf->src_type == LOCAL_X509)
    crt = get_local_cert(conf->src);
  else if (conf->src_type == LOCAL_RSA)
    rsa = get_local_rsa(conf->src);
  else
    error(EXIT_FAILURE, 0, "iternal error: unable to determine source type.");

  if (!crt && !rsa)
    error(EXIT_FAILURE, errno, "Unable to open source.");


  if (!conf->attacks) select_all_questions();
  else select_question(conf->attacks);

  if (!questions.lh_first) error(EXIT_FAILURE, 0, "No valid question selected.");

  exitcode = qa_dispose(crt, rsa);

  X509_free(crt);
  return exitcode;
}

static int
qa_dispose(X509 *crt, RSA *rsa)
{
  RSA *pub;
  RSA *priv;
  qa_question_t *q;

  if (!rsa && crt)  pub = X509_get_pubkey(crt)->pkey.rsa;
  else pub = rsa;

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
     * Run test. If the test is undecidible or either ok, go on. Otherwise,
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
      print_rsa_private(priv);
      return EXIT_SUCCESS;
    }

    /*
     * Attempt to attack the X509 certificate.
     */
    if (crt && q->ask_crt)  q->ask_crt(crt);

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
  return -1;
}

/**
 * \file allquestions.c
 *
 * \brief Quetions controller.
 *
 * Implements procedures for addign and removing questions from the global \ref
 * questions variable.
 */
#include "config.h"

#include <assert.h>
#include <string.h>
#include <bsd/sys/queue.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include "qa/questions/questions.h"

void QA_library_init(void)
{
  /* Initialize SSL Library by registering algorithms. */
  SSL_library_init();
  SSL_load_error_strings();
#ifdef HAVE_OPENMPI
  /* OpenMPI initialization */
  MPI_Init(0 , NULL);
#endif

  select_all_questions();

}

/**
 * \brief Select a single question to be used.
 *
 */
void select_question(const char *sq)
{
  qa_question_t *q, *tmpq;

  assert(questions.lh_first);

  LIST_FOREACH_SAFE(q, &questions, qs, tmpq)
    if (strcmp(q->name, sq))
      LIST_REMOVE(q, qs);
}


/**
 * \brief Run a specific question, returning the measure of security probed.
 * \return -1 if the question `q` is not suited for attacking the certificate.
 *         -2 if there has been a problem setting up the given question
 *         -3 if there has been a problem shutting down the given question
 *          0 if the certificate/key is considered secure.
 *          1.. attack measure.
 *
 */
int run_question(qa_question_t *q, X509 *crt, RSA *pub)
{
  RSA *priv;

  /* Run setup, if any */
  if (q->setup && q->setup() <= 0)
    return -2;
  /* Run test, if any. */
  if (q->test && q->test(crt) < 0)
    return -1;
  /* Attempt to attack the X509 certificate. */
  if (crt && q->ask_crt)
    q->ask_crt(crt);
  /* Attempt to attack the RSA public key */
  if (pub && q->ask_rsa &&
      (priv = q->ask_rsa(pub))) {
#ifdef DEBUG
    PEM_write_RSAPrivateKey(stdout, priv, NULL, NULL, 0, NULL, NULL);
#endif
    RSA_free(priv);
    return 1;
  }
  /* Shut down the given question. */
  if (q->teardown && q->teardown() <= 0)
    return -3;

  return 0;
}

/**
 * \brief Puts registered questions into \ref questions.
 *
 * Disposes all registered questions into a global linked list, so that future
 * procedures can iterate over all possible tests.
 */
void select_all_questions(void)
{
  LIST_INIT(&questions);

  /* REGISTER_QUESTION(ExampleQuestion); */
  REGISTER_QUESTION(DixonQuestion);
  REGISTER_QUESTION(PollardBrentRhoQuestion);
  REGISTER_QUESTION(PollardRhoQuestion);
  REGISTER_QUESTION(WilliamsQuestion);
  REGISTER_QUESTION(PollardQuestion);
  REGISTER_QUESTION(FermatQuestion);
  REGISTER_QUESTION(WienerQuestion);
  REGISTER_QUESTION(MetadataQuestion);
}

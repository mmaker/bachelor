/**
 * \file example.c
 * \brief Template for future Questions.
 *
 * This file has the purpose of showing and documenting how a
 * \ref{qa_question_t} is supposed to be used.
 *
 */
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "qa/questions/questions.h"


static BIO* out;

/**
 * \brief Example Setup.
 *
 * This functions returns false if `out` could not be opened.
 */
static int
example_question_setup(void) {
  out = BIO_new_fp(stdout, BIO_NOCLOSE);

  return (out != NULL);
}

/**
 * \brief Example Teardown.
 *
 * This function returns an error if `out` could not be closed.
 */
static int
example_question_teardown(void)
{
  return BIO_free(out);
}

/**
 * \brief Example Test.
 *
 * This function always returns zero, as its attack is undecidible.
 */
static int
example_question_test(X509* cert) {
  return 0;
}


/**
 * \brief Example Attack to X509 certificate
 */
static int
example_question_ask_crt(X509* cert)
{
  EVP_PKEY* pkey;

  pkey = X509_get_pubkey(cert);
  EVP_PKEY_print_public(out, pkey, 3, NULL);
  return 1;
}

/**
 * \brief Example Attack on a RSA key.
 */
RSA*
example_question_ask_rsa(const RSA *rsa)
{
  return NULL;
}



qa_question_t ExampleQuestion = {
  .name = "example",
  .pretty_name = "Example Question",
  .setup = example_question_setup,
  .teardown = example_question_teardown,
  .test = example_question_test,
  .ask_crt = example_question_ask_crt,
  .ask_rsa = example_question_ask_rsa
};

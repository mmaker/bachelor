#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>


#include "qa/questions/questions.h"

static BIO* out;

int example_question_setup(void) {
  out = BIO_new_fp(stdout, BIO_NOCLOSE);
  return 0;
}

int example_question_teardown(void)
{

  return 0;
}

/* XXX. apparently openssl does not allow const X509* in get_pkey() func */
int example_question_test(X509* cert) {
  return 1;
}

int example_question_ask_crt(X509* cert)
{
  EVP_PKEY* pkey;

  pkey = X509_get_pubkey(cert);
  EVP_PKEY_print_public(out, pkey, 3, NULL);
  return 1;
}

int example_question_ask_rsa(RSA *rsa)
{
  return 0;
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

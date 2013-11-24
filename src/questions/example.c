#include "questions.h"
#include "qa.h"

int example_question_setup(void) { return 0; }
int example_question_teardown(void) { return 0; }
/* XXX. apparently openssl does not allow const X509* in get_pkey() func */
int example_question_test(X509* cert) { return 1; }
int example_question_ask(X509* cert)
{
  EVP_PKEY* pkey;

  pkey = X509_get_pubkey(cert);
  EVP_PKEY_print_public(bio_out, pkey, 3, NULL);
}



struct qa_question ExampleQuestion = {
  .name = "Example Question",
  .setup = example_question_setup,
  .teardown = example_question_teardown,
  .test = example_question_test,
  .ask = example_question_ask
};

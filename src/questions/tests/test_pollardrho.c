#include <assert.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "qa/questions/questions.h"

int main(void)
{
  FILE *fp;
  RSA *pub;
  X509 *crt;
  extern qa_question_t PollardRhoQuestion;
  extern qa_question_t PollardBrentRhoQuestion;

if (!(fp = fopen("pollardrho.crt", "r")))
      return EXIT_FAILURE;

  crt = PEM_read_X509(fp, NULL, 0, NULL);
  pub = X509_get_pubkey(crt)->pkey.rsa;
  if (run_question(&PollardRhoQuestion, crt, pub) < 1)
    return EXIT_FAILURE;
  if (run_question(&PollardBrentRhoQuestion, crt, pub) < 1)
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}

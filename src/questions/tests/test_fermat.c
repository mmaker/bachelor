#include <assert.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "qa/questions/questions.h"

extern qa_question_t FermatQuestion;

int test_crt(char *in)
{
  FILE *fp;
  RSA *pub;

  if (!(fp = fopen(in, "r")))
      return EXIT_FAILURE;

  pub = PEM_read_RSAPublicKey(fp, NULL, 0, NULL);
  if (run_question(&FermatQuestion, NULL, pub) < 1)
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}

int main(void)
{
  return (test_crt("fermat.pem") || test_crt("fermat2.pem"));
}

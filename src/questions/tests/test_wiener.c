#include <assert.h>
#include <error.h>
#include <errno.h>
#include <libgen.h>
#include <string.h>


#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "qa/questions/questions.h"
#include "qa/questions/qwiener.h"


void test_wiener(void)
{
  X509 *crt;
  RSA *rsa;
  FILE *fp = fopen("wiener_test.crt", "r");

  if (!fp) exit(EXIT_FAILURE);
  crt = PEM_read_X509(fp, NULL, 0, NULL);
  if (!crt) {
    exit(EXIT_FAILURE);
  }

  rsa = X509_get_pubkey(crt)->pkey.rsa;
  /* assert(WienerQuestion.test(crt)); */
  assert(WienerQuestion.ask_rsa(rsa));
}

int main(int argc, char **argv)
{
  if (WienerQuestion.setup) WienerQuestion.setup();

  test_wiener();

  if (WienerQuestion.teardown) WienerQuestion.teardown();
  return 0;
}

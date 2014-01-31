#include <assert.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "qa/questions/questions.h"
#include "qa/questions/qpollard.h"

void test_pollard(void)
{
  X509 *crt;
  RSA *rsa;
  FILE *fp = fopen("pollard.pem", "r");

  assert(fp);
  crt = PEM_read_X509(fp, NULL, 0, NULL);
  assert(crt);

  rsa = X509_get_pubkey(crt)->pkey.rsa;
  PollardQuestion.ask_rsa(rsa);
}

int main(int argc, char **argv)
{
  PollardQuestion.setup();
  test_pollard();
  PollardQuestion.teardown();
  return 0;
}

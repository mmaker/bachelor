#include <assert.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include  "questions.h"
#include "qpollard.h"

void test_pollard(void)
{
  X509 *crt;
  FILE *fp = fopen("test/pollard.pem", "r");
  if (!fp) exit(EXIT_FAILURE);
  crt = PEM_read_X509(fp, NULL, 0, NULL);
  if (!crt) {
    exit(EXIT_FAILURE);
  }

  PollardQuestion.ask(crt);
}

int main(int argc, char **argv)
{
  PollardQuestion.setup();
  test_pollard();
  PollardQuestion.teardown();
  return 0;
}

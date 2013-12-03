#include <assert.h>
#include <string.h>

#include <openssl/x509.h>

#include "qa.h"


void test_get_local_cert(void)
{
  X509 *crt;
  EVP_PKEY *pkey;
  char path[64];

  /* get_local_cert() shall return NULL if the file does not exist. */
  strcpy(path, "/lifting/me/higher/keeps/me/lifting.crt");
  assert(!get_local_cert(path));

  strcpy(path, "/home/maker/dev/uni/thesis/src/dummy.crt");
  crt = get_local_cert(path);
  assert(crt);
  pkey = X509_get_pubkey(crt);
  assert(pkey);
  /*
   *  The certificate shall make accessible both the modulus and the public
   *  exponent.
   */
  assert(pkey->pkey.rsa->n);
  assert(pkey->pkey.rsa->e);

}


int main(int argc, char **argv)
{
  test_get_local_cert();
  return 0;
}

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "qa.h"
#include "qa_sock.h"

FILE* ferr;

void set_up(void)
{
  ferr = fopen("/dev/null", "w");

  /* Initialize SSL Library by registering algorithms. */
  SSL_library_init();
  /* trash directly network informative messages */
  if (ferr) bio_err = BIO_new_fp(ferr, BIO_NOCLOSE);
  else errno = 0;
}

void tear_down(void)
{
  fclose(ferr);
}
void test_host_port(void)
{
  char uri[100];
  char *host, *port;

  /* uris of the form host:port shall be recognized */
  strcpy(uri, "host:port");
  host_port(uri, &host, &port);
  assert(!strcmp(host, "host") &&
         !strcmp(port, "port"));
  /* uris given as urls shall be recognized */
  strcpy(uri, "https://cheese");
  host_port(uri, &host, &port);
  assert(!strcmp(host, "cheese") &&
         !strcmp(port, "https"));
  /* uris containing just a hostname shall be recognized */
  strcpy(uri, "queer");
  host_port(uri, &host, &port);
  assert(!strcmp(host, "queer") &&
         !port);
}

void test_get_remote_cert(void)
{
  X509 *crt;
  char url[100];

  /* NULL shall be returned if the host does not exists. */
  strcpy(url, "space_oddity");
  crt = get_remote_cert(url);
  assert(!crt);

#ifdef NETWORK_TESTS
  /* Google™ shall support https, and accept tcp connections on https default port. */
  strcpy(url, "google.com:443");
  crt = get_remote_cert(url);
  assert(crt);

#else
  printf("Skipping %s..\n", __func__);

#endif /* NETWORK_TESTS */
}
int main(int argc, char **argv)
{
  set_up();

  test_host_port();
  test_get_remote_cert();

  return 0;
}

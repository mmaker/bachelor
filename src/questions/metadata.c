/**
 * \file metadata.c
 * \brief Certificate Metadata Probe.
 *
 */

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "qa/questions/questions.h"


/* taken from openssl's s_client app source */
#define BUFSIZE 1024*8

#define	X509_get_serialNumber(x) ((x)->cert_info->serialNumber)

static BIO* out;

static int
metadata_question_setup(void)
{
  out = BIO_new_fp(stdout, BIO_NOCLOSE);
  return (out != NULL);
}


static int
metadata_question_teardown(void)
{
  return BIO_free(out);
}


static int
metadata_question_ask_crt(X509* crt)
{
  EVP_PKEY* pkey = NULL;
  char buf[BUFSIZE];

  /* subject informations: country, organization, common name */
  X509_NAME_oneline(X509_get_subject_name(crt), buf, sizeof(buf));
  BIO_printf(out, "s: %s\n", buf);


  /* issuer informations: country, organization, common name */
  X509_NAME_oneline(X509_get_issuer_name(crt), buf, sizeof(buf));

  /* serial number */

  /* public key */
  pkey = X509_get_pubkey(crt);

  /* public key bitlength */
  BIO_printf(out, "bitlen: %d\n", EVP_PKEY_bits(pkey));

  /* XXX.  Compression. TLS version.
   * This needs access to the socket.
   * Therefore a design change has to be taken. :( */
  /* Note: debian builds withouth sslv2 support
   * <https://lists.debian.org/debian-devel/2011/04/msg00049.html> */


    EVP_PKEY_free(pkey);
    return 1;
}

qa_question_t MetadataQuestion = {
  .name = "metadata",
  .pretty_name = "Metadata",
  .setup = metadata_question_setup,
  .teardown = metadata_question_teardown,
  .ask_crt = metadata_question_ask_crt
};

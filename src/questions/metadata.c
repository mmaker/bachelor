/**
 * \file metadata.c
 * \brief Certificate Metadata Probe.
 *
 */

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "qa/questions/questions.h"
#include "qa/questions/qstrings.h"

/* taken from openssl's s_client app source */
#define BUFSIZE 1024*8
/* for some reasons this is commented into openssl's source code x509.h */
#define	X509_get_serialNumber(x) ((x)->cert_info->serialNumber)

#define ISSUER  "issuer"
#define SUBJECT "subject"
#define SERIAL  "serial"
#define BITLEN  "bitlen"
#define PKEY    "public key"
#define NBITLEN "N bits"
#define EBITLEN "e bits"
#define MODULUS "modulus"
#define E       "pub exp"
#define NOTBEF  "not before"
#define NOTAFT  "not after"

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
  BIGNUM *serial = NULL;
  char *sserial = NULL;
  char sbuf[BUFSIZE];
  char ibuf[BUFSIZE];
  char not_after[64], not_before[64];

  /* subject informations: country, organization, common name */
  X509_NAME_oneline(X509_get_subject_name(crt), sbuf, sizeof(sbuf));
  /* issuer informations: country, organization, common name */
  X509_NAME_oneline(X509_get_issuer_name(crt), ibuf, sizeof(ibuf));
  /* serial number */
  serial = ASN1_INTEGER_to_BN(X509_get_serialNumber(crt), NULL);
  sserial = BN_bn2hex(serial);
  /* time fields */
  ASN1_TIME_str(not_before, X509_get_notBefore(crt));
  ASN1_TIME_str(not_after, X509_get_notAfter(crt));
  /* public key */
  pkey = X509_get_pubkey(crt);

  /* BIO_printf(out, "%-10s\n", PKEY); */
  /* PEM_write_bio_RSAPublicKey(out, pkey->pkey.rsa); */
  /* BIO_printf(out, "\r\n\r\n"); */
  /* public key bitlength */
  BIO_printf(out,
             "%-10s:%s\n"
             "%-10s:%s\n"
             "%-10s:%s\n"
             "%-10s:%s\n"
             "%-10s:%s\n"
             "%-10s:%d\n",
             SUBJECT, sbuf,
             ISSUER, ibuf,
             SERIAL, sserial,
             NOTBEF, not_before,
             NOTAFT, not_after,
             BITLEN, EVP_PKEY_bits(pkey));

  /* XXX.  Compression. TLS version.
   * This needs access to the socket.
   * Therefore a design change has to be taken. :( */
  /* Note: debian builds withouth sslv2 support
   * <https://lists.debian.org/debian-devel/2011/04/msg00049.html> */

  OPENSSL_free(sserial);
  BN_free(serial);
  EVP_PKEY_free(pkey);
  return 0;
}

RSA *metadata_question_ask_rsa(const RSA* rsa)
{
  char *s, *t;

  s = BN_bn2hex(rsa->e);
  t = BN_bn2hex(rsa->n);

  BIO_printf(out,
             "%-10s:%s\n"
             "%-10s:%s\n"
             "%-10s:%d\n"
             "%-10s:%d\n",
             MODULUS, t,
             E, s,
             EBITLEN, BN_num_bits(rsa->e),
             NBITLEN, BN_num_bits(rsa->n));

  OPENSSL_free(s);
  OPENSSL_free(t);
  return NULL;
}

qa_question_t MetadataQuestion = {
  .name = "metadata",
  .pretty_name = "Metadata",
  .setup = metadata_question_setup,
  .teardown = metadata_question_teardown,
  .ask_crt = metadata_question_ask_crt,
  .ask_rsa = metadata_question_ask_rsa
};

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include "qa.h"
#include "questions.h"
#include "qa_sock.h"

/**
 * \brief Connection informations.
 */
struct qa_connection {
  int socket;   /**< socket file descriptor. */
  SSL* ssl;     /**< ssl handler for this connection. */
  SSL_CTX* ctx; /**< ssl context used in this connection. */
};


/**
 * \brief Destructor for a \ref qa_connection.
 *
 * Closes the socket, shuts down the connection, and frees all memory used for
 * holding the connection.
 * \note Input might be partial (ex. a socket exists, but not no ssl session).
 *
 * \param c   The connection to be freed.
 */
static void qa_connection_free(struct qa_connection* c)
{
  if (c->socket)
    close(c->socket);
  if (c->ssl) {
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
  }
  if (c->ctx)
    SSL_CTX_free(c->ctx);

  free(c);
}

void qa_abort(const char *reason)
{
  //ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}


static int verify_callback(int ok, X509_STORE_CTX* ctx)
{
  return ok;
}


/**
 * \brief Set up a new ssl connection.
 *
 * Create a new \ref qa_connection, turning on OpenSSL (if not yet started), and
 * opening a socket with the target server over ssl.
 *
 * \param[in] conf  Configuration holding informations about the target.
 * \return          The new connection.
 */
struct qa_connection* qa_connection_new(const struct qa_conf* conf)
{
  struct qa_connection* c;
  int err;

  c = malloc(sizeof(struct qa_connection));
  if (!c) qa_abort("No Memory.");

  /* Initialize SSL Library by registering algorithms. */
  SSL_library_init();


  c->ctx = SSL_CTX_new(SSLv23_client_method());
  if (!c->ctx) {
    qa_connection_free(c);
    qa_abort("Cannot create context");
  }

  /* is also the default. lol. */
  SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, verify_callback);
  c->ssl = SSL_new(c->ctx);
  if (!c->ssl) {
    qa_connection_free(c);
    qa_abort("Cannot create ssl handle");
  }

  if (!(c->socket = init_client(conf))) {
    qa_connection_free(c);
    qa_abort("Cannot create socket.");
  }

  if (!SSL_set_fd(c->ssl, c->socket)) {
    qa_connection_free(c);
    qa_abort("Cannot bind socket to ssl session");
  }

  /* XXX. Handle errors appropriately using error codes from OpenSSL */
  err = SSL_connect(c->ssl);
  if (err != 1) {
    qa_connection_free(c);
    qa_abort("Cannot Connect");
  }

  SSL_set_connect_state(c->ssl);

  return c;
}


/**
 * \brief Given an initial configuration, stuctures the program flow.
 *
 * \param[in] args   Initial configuration given from a frontend.
 */
int qa_init(const struct qa_conf* args)
{
  X509 *crt;
  struct qa_connection *c;
  struct qa_question *q;

  /* bind stdout to a BIO shit to be used externally */
  bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* create a new connection, and download the certificate */
  c = qa_connection_new(args);
  crt = SSL_get_peer_certificate(c->ssl);
  if (!crt) qa_abort("Cannot obtain certificate");

  register_all_questions();
for (q=questions.lh_first; q; q = q->qs.le_next) {
    q->setup();
    q->test(crt);
    q->ask(crt);
    q->teardown();
  }

  qa_connection_free(c);

  return 0;
}

#ifndef _QA_QUESTIONS_H_
#define _QA_QUESTIONS_H_

#include <sys/queue.h>

#include <openssl/x509.h>

/**
 * A question: name, command-line name, callbacks.
 */
typedef struct qa_question {
  const char* name;    /**< short name - name given as command-line argument */
  const char* pretty_name;    /**< full name - name used for identifying the question */

  int (* setup) (void);    /**< setup callback - initializes static glabal
                              variables.
                              Return <= 0 in case of error */
  int (* teardown) ();    /**< teardown callback - frees static global
                             variables
                             Return <= 0 in case of error*/
  int (* test) (X509 *cert);   /**< test callback - assert the attack can be
                                  performed over the certificate cert.
                                  Return 1 if it is possible to attack the
                                  certificate, -1 if not, 0 if undecidible. */
  RSA* (* ask_rsa) (const RSA *rsa);    /**< ask_rsa callback - attack the RSA
                                           key rsa. Return NULL if the key was
                                           not broken, a valid private key
                                           structure otherwise.*/
  int (* ask_crt) (X509 *crt);    /**< ask_crt callback - attack the certificate
                                     crt.
                                     XXX. Return type has still to be
                                     established here.
                                     XXX. apparently openssl does not allow const
                                     X509* in get_pkey() func. */

  LIST_ENTRY(qa_question) qs;
} qa_question_t;

LIST_HEAD(listhead, qa_question) questions;

void select_question(const char *);
void select_all_questions(void);

void QA_library_init(void);

#define REGISTER_QUESTION(q)                      \
  do {                                            \
      extern struct qa_question q;                \
      LIST_INSERT_HEAD(&questions, &q, qs);       \
  } while (0);


#endif /* _QA_QUESTIONS_H_ */

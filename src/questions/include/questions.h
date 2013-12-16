#ifndef _QA_QUESTIONS_H_
#define _QA_QUESTIONS_H_

#include <sys/queue.h>

#include <openssl/x509.h>

/**
 * A question: name, command-line name, callbacks.
 */
typedef struct qa_question {
  const char* name;            /**< short name - name given as command-line argument */
  const char* pretty_name;     /**< full name - name used for identifying the question */

  int (* setup) (void);        /**< setup callback - initializes static glabal
                                  variables.*/
  int (* teardown) ();         /**< teardown callback - frees static global
                                  variables */
  int (* test) (X509 *cert);   /**< test callback - assert the attack can be
                                  performed over the certificate cert */
  int (* ask_rsa) (RSA *rsa);  /**< ask_rsa callback - attack the RSA key rsa */
  int (* ask_crt) (X509 *crt); /**< ask_crt callback - attack the certificate
                                  crt */

  LIST_ENTRY(qa_question) qs;
} qa_question_t;

LIST_HEAD(listhead, qa_question) questions;

void select_question(const char *);
void select_all_questions(void);

#define REGISTER_QUESTION(q)                      \
  {                                               \
      extern struct qa_question q;                \
      LIST_INSERT_HEAD(&questions, &q, qs);       \
  }


#endif /* _QA_QUESTIONS_H_ */

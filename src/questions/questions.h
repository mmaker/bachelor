#ifndef _QA_QUESTIONS_H_
#define _QA_QUESTIONS_H_

#include <sys/queue.h>

#include <openssl/x509.h>


struct qa_question {
  const char* name;
  int (* setup) (void);
  int (* teardown) ();
  int (* test) (X509* cert);
  int (* ask) (X509* cert);

  LIST_ENTRY(qa_question) qs;
};


LIST_HEAD(listhead, qa_question) questions;

void register_all_questions(void);


#endif /* _QA_QUESTIONS_H_ */

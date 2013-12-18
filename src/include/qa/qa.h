#ifndef _QA_H_
#define _QA_H_

#include <openssl/bio.h>

struct qa_conf {
  enum sources {
    NONE, LOCAL_X509, LOCAL_RSA, REMOTE
  } src_type;
  char *src;
  char *attacks;
};


int qa_init(const struct qa_conf* args);

void qa_dispose(X509 *crt, RSA *rsa);

X509* get_local_cert(const char *src);

#endif   /* _QA_H_ */

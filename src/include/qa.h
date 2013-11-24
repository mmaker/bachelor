#ifndef _QA_H_
#define _QA_H_

#include <openssl/bio.h>

struct qa_conf {
  char *host;
  char *port;
};


BIO* bio_out;

int qa_init(const struct qa_conf* args);


#endif   /* _QA_H_ */

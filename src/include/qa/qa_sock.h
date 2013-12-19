#ifndef _QA_SOCK_H_
#define _QA_SOCK_H_

#include "qa/qa.h"

extern BIO* bio_out;
extern BIO* bio_err;

int init_client(const char *host, const char *port);

int host_port(char *uri, char **host, char **service);

X509* get_remote_cert(char *address);

#endif   /* _QA_SOCK_H_ */

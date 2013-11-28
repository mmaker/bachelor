#ifndef _QA_SOCK_H_
#define _QA_SOCK_H_

#include "qa.h"

int init_client(const struct qa_conf *options);

int host_port(char *uri, char **host, char **service);

X509* get_remote_cert(char *address);

#endif   /* _QA_SOCK_H_ */

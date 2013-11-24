#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "qa.h"

#define SOCKET_PROTOCOL 0
#define INVALID_SOCKET  (-1)

int init_client(const struct qa_conf *options)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s;
  int i;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  if ((i=getaddrinfo(options->host, options->port, NULL, &result))) {
    fprintf(stderr, "Error: %s\n", gai_strerror(i));
    exit(EXIT_FAILURE);
  }

  for (rp=result; rp; rp = rp->ai_next)  {
    s = socket(rp->ai_family,
               rp->ai_socktype,
               rp->ai_protocol);
    if (s == INVALID_SOCKET) continue;

    if (rp->ai_protocol == SOCK_STREAM) {
       i = 0;
       i = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*) &i, sizeof(i));
       if (i < 0) exit(EXIT_FAILURE);
    }

    if (connect(s, rp->ai_addr, rp->ai_addrlen) != -1) break;
  }
  if (!rp) exit(EXIT_FAILURE);

  return s;
}

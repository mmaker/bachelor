/**
 * \file cmdline.c
 *
 * \brief Commandline utilities.
 *
 * Frontend to QA, proving an easy command line inteface according with the
 * POSIX standard.
 */
#define _GNU_SOURCE

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "qa.h"

#define QA_DEFAULT_PORT "443"


/**
 * \brief Converts a uri into a tuple {host, service}.
 *
 * Parses an input string containing a host and (maybe) a service/port.
 * Valid options are:
 *  - service://hostname
 *  - hostname
 *  - hostname:port
 * The resulting tuple will be stored in params \ref host and \ref service.
 *
 * \param[in]  uri     The input uri.
 * \param[out] host    Place where to store parsed host.
 * \param[out] service Place where to store parsed service.
 *
 * \note \ref uri might be modified during parsing.
 */
static void host_port(char* uri, char** host, char** service)
{
  char* c;

  if (!(c = strchr(uri, ':')))
    *host = uri;
  else {
    *c = '\0';
    if (c[1] != '/' && c[2] == '/') {
      *service = uri;
      *host = c+3;
    } else {
      *service = c+1;
      *host = uri;
    }
  }
}


/**
 * \brief Prints the usage message, then exit.
 *
 * Prints in POSIX format the various options for using qa.
 *
 */
void usage(void)
{
  static const char* help_message = "%s usage: %s"
    " [-p PORT]"
    " <target>"
    " \n";
  fprintf(stderr, help_message,
          program_invocation_short_name,
          program_invocation_name);
}


int main(int argc, char** argv)
{
  char opt;
  int option_index;
  size_t i;

  struct option long_options[] = {
    {"help", required_argument, NULL, 'h'},
    {"port", required_argument, NULL, 'p'},
    {0, 0, 0, 0}
  };
  static const char* short_options = "h:p:";

  struct qa_conf conf = {
    .host = NULL,
    .port = NULL,
  };

  while ((opt=getopt_long(argc, argv,
                          short_options, long_options,
                          &option_index)) != -1)
    switch (opt) {
    case 'h':
      usage();
      exit(EXIT_SUCCESS);
      break;
    case 'p':
      conf.port = optarg;
      break;
    case '?':
    default:
      usage();
      exit(EXIT_FAILURE);
    }

  if (optind < argc && !strcmp(argv[optind], "--")) optind++;
  if (optind != argc-1) {
    usage();
    exit(EXIT_FAILURE);
  }

  host_port(argv[optind], &conf.host, &conf.port);
  if (!conf.port) conf.port = QA_DEFAULT_PORT;

  return qa_init(&conf);
}

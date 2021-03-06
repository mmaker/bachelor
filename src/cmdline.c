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

#include <bsd/sys/queue.h>

#include "qa/qa.h"
#include "qa/questions/questions.h"

/**
 * \brief Prints the usage message, then exit.
 *
 * Prints in POSIX format the various options for using qa.
 *
 */
void usage(void)
{
  qa_question_t *q;
  static const char* help_message = "%s usage: %s"
    " [-r HOST:port | -f X509 | -R RSA]"
    " [-a ATTACK]"
    " \n\n"
    "If no argument is supplied, by default a public RSA key is expected "
    "to be read from the standard input.\n\n"
    "Available attacks: \n";
  fprintf(stderr, help_message,
          program_invocation_short_name,
          program_invocation_name);
  LIST_FOREACH(q, &questions, qs)
    fprintf(stderr, "%-10s\t\t%s\n", q->name, q->pretty_name);
  fprintf(stderr, "\n");
}

void conflicting_args(void)
{
  fprintf(stderr, "Conflicting arguments.\n");
  usage();
  exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
  char opt;
  int option_index;

  struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"remote", required_argument, NULL, 'r'},
    {"file", required_argument, NULL, 'f'},
    {"rsa", required_argument, NULL, 'R'},
    {0, 0, 0, 0}
  };
  static const char* short_options = "hr:f:a:R:";

  struct qa_conf conf = {
    .src_type = NONE,
    .attacks = NULL,
  };

  QA_library_init();

  while ((opt=getopt_long(argc, argv,
                          short_options, long_options,
                          &option_index)) != -1)
    switch (opt) {
    case 'h':
      usage();
      exit(EXIT_SUCCESS);
      break;
    case 'f':
      if (conf.src_type != NONE) conflicting_args();
      conf.src_type = LOCAL_X509;
      conf.src = optarg;
      break;
    case 'r':
      if (conf.src_type != NONE) conflicting_args();
      conf.src_type = REMOTE;
      conf.src = optarg;
      break;
    case 'R':
      if (conf.src_type != NONE) conflicting_args();
      conf.src_type = LOCAL_RSA;
      conf.src = optarg;
      break;
    case 'a':
      conf.attacks = optarg;
      break;
    case '?':
    default:
      usage();
      exit(EXIT_FAILURE);
    }

  if (conf.src_type == NONE)  {
    conf.src_type = LOCAL_RSA;

    if (optind == argc)
      conf.src = "-";
    else if (optind == argc-1)
      conf.src = argv[optind];
    else if (optind == argc-2 && !strcmp(argv[optind], "--"))
      conf.src = argv[optind+1];
    else {
        usage();
        exit(EXIT_FAILURE);
      }
  }

  return qa_init(&conf);
}

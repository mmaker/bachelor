/**
 * \file allquestions.c
 *
 * \brief Quetions controller.
 *
 * Implements procedures for addign and removing questions from the global \ref
 * questions variable.
 */
#include "config.h"

#include <assert.h>
#include <string.h>
#include <bsd/sys/queue.h>

#include <openssl/ssl.h>
#include <mpi.h>

#include "qa/questions/questions.h"

void QA_library_init(void)
{
  /* Initialize SSL Library by registering algorithms. */
  SSL_library_init();
  SSL_load_error_strings();
#ifdef HAVE_OPENMPI
  /* OpenMPI initialization */
  MPI_Init(0 , NULL);
#endif

}

/**
 * \brief Select a single question to be used.
 *
 */
void select_question(const char *sq)
{
  qa_question_t *q, *tmpq;

  select_all_questions();
  assert(questions.lh_first);

  LIST_FOREACH_SAFE(q, &questions, qs, tmpq)
    if (strcmp(q->name, sq))
      LIST_REMOVE(q, qs);
}

/**
 * \brief Puts registered questions into \ref questions.
 *
 * Disposes all registered questions into a global linked list, so that future
 * procedures can iterate over all possible tests.
 */
void select_all_questions(void)
{
  LIST_INIT(&questions);

  REGISTER_QUESTION(ExampleQuestion);
  REGISTER_QUESTION(WienerQuestion);
  REGISTER_QUESTION(PollardQuestion);
  REGISTER_QUESTION(FermatQuestion);
  REGISTER_QUESTION(MetadataQuestion);
  REGISTER_QUESTION(PollardRhoQuestion);
  REGISTER_QUESTION(WilliamsQuestion);
  REGISTER_QUESTION(DixonQuestion);
  REGISTER_QUESTION(PollardBrentRhoQuestion);
}

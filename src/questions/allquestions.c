/**
 * \file allquestions.c
 *
 * \brief Quetions controller.
 *
 * Implements procedures for addign and removing questions from the global \ref
 * questions variable.
 */

#include <assert.h>
#include <string.h>
#include <bsd/sys/queue.h>

#include "qa/questions/questions.h"

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

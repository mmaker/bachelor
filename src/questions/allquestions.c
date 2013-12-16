#include <assert.h>
#include <string.h>
#include <sys/queue.h>

#include "qa/questions/questions.h"

/**
 * \brief Select a single question to be used.
 *
 */
void select_question(const char *sq)
{
  qa_question_t *q;

  select_all_questions();
  assert(questions.lh_first);

  for (q = questions.lh_first; q && strcmp(q->name, sq); q = questions.lh_first)
    LIST_REMOVE(q, qs);
  if (!q) return;

  for (q = q->qs.le_next; q; q = q->qs.le_next)
    if (strcmp(q->name, sq))
      LIST_REMOVE(q, qs);
}

/**
 * /brief Puts registered questions into \ref questions.
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
}

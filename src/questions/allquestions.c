#include <sys/queue.h>

#include "questions.h"


#define REGISTER_QUESTION(q)                      \
  {                                               \
      extern struct qa_question q;                \
      LIST_INSERT_HEAD(&questions, &q, qs);       \
  }

/**
 * /brief Puts registered questions into \ref questions.
 *
 * Disposes all registered questions into a global linked list, so that future
 * procedures can iterate over all possible tests.
 */
void register_all_questions(void)
{
  LIST_INIT(&questions);

  REGISTER_QUESTION(ExampleQuestion);
  REGISTER_QUESTION(WienerQuestion);
  REGISTER_QUESTION(PollardQuestion);
}

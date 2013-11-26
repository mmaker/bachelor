#ifndef _QA_WIENER_H_
#define _QA_WIENER_H

#include <stdlib.h>

struct cf {
  struct fraction {
    long h;
    long k;
  } fs[3];
  short int i;
  double x;
  long a;
};

void cfrac_init(struct cf* f, double x);
struct fraction* cfrac_next(struct cf* f);

extern struct qa_question WienerQuestion;
#endif

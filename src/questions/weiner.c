#include <openssl/x509.h>
#include <math.h>
#include <stdlib.h>

#include "questions.h"
#include "weiner.h"

int wiener_question_setup(void) { return 0; }
int wiener_question_teardown(void) { return 0; }

int wiener_question_test(X509* cert) { return 1; }


void cfrac_init(struct cf* f, double x)
{
  f->fs[0].h = 0;
  f->fs[0].k = 1;

  f->fs[1].h = 1;
  f->fs[1].k = 0;

  f->i = 2;
  f->x = x;
}

struct fraction cfrac_next(struct cf* f)
{
  long a = lrint(floor(f->x));
  struct fraction ith_cf, *fs = f->fs;

  ith_cf.h = fs[f->i%3].h = a*fs[(f->i-1)%3].h + fs[(f->i-2)%3].h;
  ith_cf.k = fs[f->i%3].k = a*fs[(f->i-1)%3].k + fs[(f->i-2)%3].k;
  f->x = 1./(f->x-a);
  f->i = (f->i+1) % 3;

  return ith_cf;
}

int wiener_question_ask(X509* cert)
{
  return 0;
}



struct qa_question WienerQuestion = {
  .name = "Wiener",
  .setup = wiener_question_setup,
  .teardown = wiener_question_teardown,
  .test = wiener_question_test,
  .ask = wiener_question_ask
};

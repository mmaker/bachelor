#include <openssl/x509.h>
#include <math.h>
#include <stdlib.h>

#include "questions.h"
#include "qwiener.h"

#define EPS 1e-10

int wiener_question_setup(void) { return 0; }
int wiener_question_teardown(void) { return 0; }

int wiener_question_test(X509* cert) { return 1; }

/**
 * \brief Initialized a continued fraction.
 *
 * A continued fraction for a floating number x can be expressed as a series
 *  <a₀; a₁, a₂…, aₙ>
 * such that
 * <pre>
 *
 *                1
 *  x = a₀ + ⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽⎽
 *                    1
 *           a₁ + ⎽⎽⎽⎽⎽⎽⎽⎽⎽
 *                 a₂ + …
 *
 * </pre>
 * , where for each i < n, there exists an approximation hᵢ / kᵢ.
 * By definition,
 *   a₋₁ = 0
 *   h₋₁ = 1    h₋₂ = 0
 *   k₋₁ = 0    k₋₂ = 1
 */
void cfrac_init(struct cf* f, double x)
{
  f->fs[0].h = 0;
  f->fs[0].k = 1;

  f->fs[1].h = 1;
  f->fs[1].k = 0;

  f->i = 2;
  f->x = x;
  f->a = 0;
}


/**
 * \brief Produces the next fraction.
 *
 * Each new approximation hᵢ/kᵢ is defined recursively as:
 *   hᵢ = aᵢhᵢ₋₁ + hᵢ₋₂
 *   kᵢ = aᵢkᵢ₋₁ + kᵢ₋₂
 * Meanwhile each new aᵢ is simply the integer part of x.
 *
 *
 * \param f   The continued fraction.
 * \return NULL if the previous fraction approximates at its best the number,
 *         a pointer to the next fraction in the series othw.
 */
struct fraction* cfrac_next(struct cf* f)
{
  struct fraction *fs = f->fs;
  struct fraction *ith_fs = &fs[f->i];

  f->a = lrint(floor(f->x));
  if (f->x - f->a < EPS) return NULL;

  fs[f->i].h = f->a * fs[(f->i-1+3) % 3].h + fs[(f->i-2+3) % 3].h;
  fs[f->i].k = f->a * fs[(f->i-1+3) % 3].k + fs[(f->i-2+3) % 3].k;

  f->i = (f->i + 1) % 3;
  f->x = 1. / (f->x - f->a);

  return ith_fs;
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

#ifndef _QA_DIXON_H_
#define _QA_DIXON_H_

extern struct qa_question DixonQuestion;

typedef struct matrix {
  char  **M;
  size_t f;
  size_t r;
} matrix_t;


matrix_t* identity_matrix_new(int d);

matrix_t* matrix_new(int r, int c);

void matrix_free(matrix_t *m);

matrix_t *kernel(matrix_t *m);

void discover_smooth(BIGNUM *y, BIGNUM *x, BIGNUM *n,
                     BN_CTX *ctx, char *v, size_t len);

int dixon_smooth(BIGNUM *x, BN_CTX *ctx, char *v, size_t len);


RSA *dixon_factorize(const RSA *rsa);
#endif /* _QA_DIXON_H_ */

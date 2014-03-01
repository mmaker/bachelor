#ifndef _QA_QSTRINGS_H_
#define _QA_QSTRINGS_H_

int
is_vzero(const void *v, size_t len);

void
vxor(void *u, const void *v, const void *w, size_t len);

int
ASN1_TIME_str(char *dest, const ASN1_TIME *tm);

#endif /* _QA_QSTRINGS_H_ */

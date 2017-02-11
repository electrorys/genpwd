#ifndef _GENPWD_H
#define _GENPWD_H

#include <stdint.h>
#include "mkpwd.h"
#include "tf1024.h"

int selftest(void);

void loadsalt(const char *fname, const unsigned char **P, size_t *B);

void b64_encode(char *dst, const unsigned char *src, size_t length);
void stripchr(char *s, const char *rem);

void hash85(char *dst, const unsigned char *src, size_t len);
void hash95(char *dst, const unsigned char *src, size_t len);

#endif

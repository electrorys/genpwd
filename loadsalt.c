#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "genpwd.h"

void loadsalt(const char *fname, const unsigned char **P, size_t *B)
{
	FILE *f = NULL;
	unsigned char *p;
	unsigned char buf[256]; size_t b, l;

	if (!strcmp(fname, "-")) { f = stdin; goto _noopen; }
	f = fopen(fname, "rb");
	if (!f) { perror(fname); exit(2); }

_noopen:
	p = genpwd_malloc(B ? *B : 1);
	if (!p) xerror("Can't get memory for salt");

	b = 0;
	while (1) {
		if (feof(f)) break;
		l = fread(buf, 1, sizeof(buf), f);
		if (ferror(f)) { fclose(f); perror("read"); exit(2); }
		p = genpwd_realloc(p, b + l); memset(p + b, 0, l);
		memmove(p + b, buf, l); b += l;
	}

	fclose(f);
	memset(buf, 0, sizeof(buf));

	if (B) *B = b;
	*P = p;
}

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "mkpwd.h"
#include "genpwd.h"

static void old_stripchr(char *s, const char *rem)
{
	const char *rst = rem;
	char *d = s;
	int add = 0;

	while (*s) {
		while (*rem) {
			if (*s != *rem) add = 1;
			else {
				add = 0;
				break;
			}
			rem++;
		}

		if (add) *d++ = *s;

		s++;
		rem = rst;
	}

	memset(d, 0, s-d);
}

static size_t remove_chars(char *str, size_t max, const char *rm)
{
	const char *urm;
	char *s;
	size_t ntail;

	urm = rm; ntail = 0;
	while (*urm) {
_findanother:	s = memchr(str, *urm, max);
		if (s) {
			memmove(s, s+1, max-(s-str)-1);
			ntail++;
			goto _findanother;
		}
		urm++;
	}
	memset(str+(max-ntail), 0, ntail);
	return max-ntail;
}

#define reterror(p, s) do { 					\
		genpwd_free(bpw);				\
		genpwd_free(ret);				\
		if (p) genpwd_free(p);				\
		mkpwa->result = NULL;				\
		mkpwa->szresult = 0;				\
		if (s) mkpwa->error = genpwd_strdup(s);		\
		else mkpwa->error = NULL;			\
		return MKPWD_NO;				\
	} while (0)
int mkpwd(struct mkpwd_args *mkpwa)
{
	sk1024_ctx ctx;
	void *ret, *bpw;
	char *uret;
	size_t x;

	if (!mkpwa) return MKPWD_NO;
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)
	|| !mkpwa->id
	|| mkpwa->format == 0
	|| mkpwa->length == 0) return MKPWD_NO;

	bpw = genpwd_malloc(TF_KEY_SIZE);
	ret = genpwd_malloc(MKPWD_MAXPWD);

	sk1024_init(&ctx, TF_MAX_BITS, 0);
	sk1024_update(&ctx, mkpwa->pwd, strnlen(mkpwa->pwd, MKPWD_MAXPWD));
	sk1024_update(&ctx, mkpwa->salt, mkpwa->szsalt);
	sk1024_update(&ctx, mkpwa->id, strnlen(mkpwa->id, MKPWD_MAXPWD));
	sk1024_final(&ctx, bpw);
	memset(&ctx, 0, sizeof(sk1024_ctx));

	if (mkpwa->passes) {
		for (x = 0; x < mkpwa->passes; x++)
			sk1024(bpw, TF_KEY_SIZE, bpw, TF_MAX_BITS);
	}

	if (mkpwa->format == MKPWD_FMT_B64) {
		base64_encode(ret, bpw, TF_KEY_SIZE);
		remove_chars(ret, MKPWD_MAXPWD, "./+=");
		if (!getenv("_GENPWD_OLDB64")) {
			void *tp = genpwd_malloc(MKPWD_MAXPWD);
			b64_encode(tp, bpw, TF_KEY_SIZE);
			old_stripchr(tp, "./+=");
			if (strcmp(ret, tp) != 0)
				reterror(tp, "New base64 failed");
			genpwd_free(tp);
		}
	}
	else if (mkpwa->format == MKPWD_FMT_A85) {
		base85_encode(ret, bpw, TF_KEY_SIZE);
		if (!getenv("_GENPWD_OLDB85")) {
			void *tp = genpwd_malloc(MKPWD_MAXPWD);
			hash85(tp, bpw, TF_KEY_SIZE);
			if (strcmp(ret, tp) != 0)
				reterror(tp, "New base85 failed");
			genpwd_free(tp);
		}
	}
	else if (mkpwa->format == MKPWD_FMT_A95) {
		base95_encode(ret, bpw, TF_KEY_SIZE);
		if (!getenv("_GENPWD_OLDB95")) {
			void *tp = genpwd_malloc(MKPWD_MAXPWD);
			hash95(tp, bpw, TF_KEY_SIZE);
			if (strcmp(ret, tp) != 0)
				reterror(tp, "New base95 failed");
			genpwd_free(tp);
		}
	}
	else if (mkpwa->format < 0) {
		void *tp = genpwd_malloc(4);
		unsigned char *ubpw;
		char *utp, *uret;
		size_t d, y;

		for (x = 0, d = 0, ubpw = bpw, uret = ret, utp = tp; x < TF_KEY_SIZE; x++) {
			switch (mkpwa->format) {
			case MKPWD_FMT_DEC:
				y = snprintf(utp, 4, "%hhu", ubpw[x]);
				if (ubpw[x] > 100) {
					if (utp[0] == '1') utp[2]++;
					if (utp[0] == '2') utp[2] += 2;
					if (utp[2] > '9') utp[2] -= 10;
					y--;
				}
				xstrlcpy(uret+d,
					ubpw[x] > 100 ? utp+1 : utp,
					MKPWD_MAXPWD - d);
				d += y;
				break;
			case MKPWD_FMT_HEX:
				d += snprintf(uret+d, 3, "%hhx", ubpw[x]);
				break;
			case MKPWD_FMT_OCT:
				d += snprintf(uret+d, 4, "%hho", ubpw[x]);
				break;
			}
		}

		genpwd_free(tp);
	}
	else reterror(NULL, "Unsupported mkpwd format");

	uret = ret;
	memmove(ret, uret+mkpwa->offset, mkpwa->length);
	memset(uret+mkpwa->length, 0, MKPWD_MAXPWD - mkpwa->length);

	genpwd_free(bpw);
	mkpwa->result = ret;
	mkpwa->szresult = strnlen(ret, MKPWD_MAXPWD);
	mkpwa->error = NULL;
	return MKPWD_YES;
}

int mkpwbuf(struct mkpwd_args *mkpwa)
{
	sk1024_ctx ctx;
	size_t x;
	void *ret;

	if (!mkpwa) return MKPWD_NO;
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)
	|| !mkpwa->id) return MKPWD_NO;

	ret = genpwd_malloc(mkpwa->length);

	sk1024_init(&ctx, TF_TO_BITS(mkpwa->length), 0);
	sk1024_update(&ctx, mkpwa->pwd, strnlen(mkpwa->pwd, MKPWD_MAXPWD));
	sk1024_update(&ctx, mkpwa->salt, mkpwa->szsalt);
	sk1024_update(&ctx, mkpwa->id, strnlen(mkpwa->id, MKPWD_MAXPWD));
	sk1024_final(&ctx, ret);
	memset(&ctx, 0, sizeof(sk1024_ctx));

	if (mkpwa->passes) {
		for (x = 0; x < mkpwa->passes; x++)
			sk1024(ret, mkpwa->length, ret, TF_TO_BITS(mkpwa->length));
	}

	mkpwa->result = ret;
	mkpwa->szresult = mkpwa->length;
	mkpwa->error = NULL;
	return MKPWD_YES;
}

int mkpwd_hint(struct mkpwd_args *mkpwa)
{
	void *bpw, *ret;
	char *ubpw;
	sk1024_ctx ctx;

	if (!mkpwa) return MKPWD_NO;
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)) return MKPWD_NO;

	bpw = ubpw = genpwd_malloc(TF_FROM_BITS(16));
	ret = genpwd_malloc(8);

	sk1024_init(&ctx, 16, 0);
	sk1024_update(&ctx, mkpwa->pwd, strnlen(mkpwa->pwd, MKPWD_MAXPWD));
	sk1024_update(&ctx, mkpwa->salt, mkpwa->szsalt);
	sk1024_final(&ctx, bpw);
	memset(&ctx, 0, sizeof(sk1024_ctx));

	snprintf(ret, 8, "%02hhx%02hhx", ubpw[0], ubpw[1]);

	genpwd_free(bpw);
	mkpwa->result = ret;
	mkpwa->szresult = 4;
	mkpwa->error = NULL;
	return MKPWD_YES;
}

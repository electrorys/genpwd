#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "mkpwd.h"
#include "genpwd.h"

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
	struct skein sk;
	void *ret, *bpw;
	char *uret;
	size_t x;

	if (!mkpwa) return MKPWD_NO;
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)
	|| !mkpwa->id
	|| mkpwa->format == 0
	|| mkpwa->length == 0) return MKPWD_NO;

	bpw = genpwd_malloc(SKEIN_DIGEST_SIZE);
	ret = genpwd_malloc(MKPWD_MAXPWD);

	skein_init(&sk, TF_MAX_BITS);
	skein_update(&sk, mkpwa->pwd, strnlen(mkpwa->pwd, MKPWD_MAXPWD));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt);
	skein_update(&sk, mkpwa->id, strnlen(mkpwa->id, MKPWD_MAXPWD));
	skein_final(bpw, &sk);

	if (mkpwa->passes) {
		for (x = 0; x < mkpwa->passes; x++)
			skein(bpw, TF_MAX_BITS, bpw, SKEIN_DIGEST_SIZE);
	}

	if (mkpwa->format == MKPWD_FMT_B64) {
		base64_encode(ret, bpw, TF_KEY_SIZE);
		remove_chars(ret, MKPWD_MAXPWD, "./+=");
	}
	else if (mkpwa->format == MKPWD_FMT_A85) {
		base85_encode(ret, bpw, TF_KEY_SIZE);
	}
	else if (mkpwa->format == MKPWD_FMT_A95) {
		base95_encode(ret, bpw, TF_KEY_SIZE);
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

int mkpwd_key(struct mkpwd_args *mkpwa)
{
	struct skein sk;
	size_t x;
	void *ret;

	if (!mkpwa) return MKPWD_NO;
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)
	|| !mkpwa->id) return MKPWD_NO;

	ret = genpwd_malloc(mkpwa->length);

	skein_init(&sk, TF_TO_BITS(mkpwa->length));
	skein_update(&sk, mkpwa->pwd, strnlen(mkpwa->pwd, MKPWD_MAXPWD));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt);
	skein_update(&sk, mkpwa->id, strnlen(mkpwa->id, MKPWD_MAXPWD));
	skein_final(ret, &sk);

	if (mkpwa->passes) {
		for (x = 0; x < mkpwa->passes; x++)
			skein(ret, TF_TO_BITS(mkpwa->length), ret, mkpwa->length);
	}

	mkpwa->result = ret;
	mkpwa->szresult = mkpwa->length;
	mkpwa->error = NULL;
	return MKPWD_YES;
}

int mkpwd_hint(struct mkpwd_args *mkpwa)
{
	struct skein sk;
	void *bpw, *ret;
	char *ubpw;

	if (!mkpwa) return MKPWD_NO;
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)) return MKPWD_NO;

	bpw = ubpw = genpwd_malloc(TF_FROM_BITS(16));
	ret = genpwd_malloc(8);

	skein_init(&sk, 16);
	skein_update(&sk, mkpwa->pwd, strnlen(mkpwa->pwd, MKPWD_MAXPWD));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt);
	skein_final(bpw, &sk);

	snprintf(ret, 8, "%02hhx%02hhx", ubpw[0], ubpw[1]);

	genpwd_free(bpw);
	mkpwa->result = ret;
	mkpwa->szresult = 4;
	mkpwa->error = NULL;
	return MKPWD_YES;
}

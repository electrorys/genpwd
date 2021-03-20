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

static void init_mkpwa(struct mkpwd_args *mkpwa)
{
	if (mkpwa->pwdmax == 0 || mkpwa->pwdmax >= SIZE_MAX) mkpwa->pwdmax = 256;
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
	init_mkpwa(mkpwa);
	if (!mkpwa->pwd
	|| !mkpwa->salt
	|| !mkpwa->id
	|| mkpwa->format == 0
	|| mkpwa->length == 0
	|| mkpwa->length >= mkpwa->pwdmax) return MKPWD_NO;

	bpw = genpwd_malloc(SKEIN_DIGEST_SIZE);
	ret = genpwd_malloc(mkpwa->pwdmax);

	skein_init(&sk, TF_MAX_BITS);
	skein_update(&sk, mkpwa->pwd, mkpwa->szpwd ? mkpwa->szpwd : strnlen(mkpwa->pwd, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt ? mkpwa->szsalt : strnlen(mkpwa->salt, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->id, mkpwa->szid ? mkpwa->szid : strnlen(mkpwa->id, mkpwa->pwdmax));
	skein_final(bpw, &sk);

	if (mkpwa->passes) {
		for (x = 0; x < mkpwa->passes; x++)
			skein(bpw, TF_MAX_BITS, bpw, SKEIN_DIGEST_SIZE);
	}

	if (mkpwa->format == MKPWD_FMT_B64) {
		base64_encode(ret, bpw, TF_KEY_SIZE);
		remove_chars(ret, mkpwa->pwdmax, "./+=");
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

		ret = genpwd_realloc(ret, genpwd_szalloc(ret)+(mkpwa->pwdmax/4));

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
					mkpwa->pwdmax - d);
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
	else if (mkpwa->format == MKPWD_FMT_CPWD) {
		void *rndata;
		char c, *s, *d;
		size_t x, i;

		bpw = genpwd_realloc(bpw, mkpwa->length > TF_KEY_SIZE ? mkpwa->length : TF_KEY_SIZE);
		rndata = genpwd_malloc(tf_prng_datasize());

		tf_prng_seedkey_r(rndata, bpw);

		s = bpw;
		for (x = 0; x < mkpwa->length/2; x++) {
_tryagainc1:		c = (char)tf_prng_range_r(rndata, 0x20, 0x7f);
			if (strchr(MKPWD_ALPHA_STRING, c)) {
				*s = c;
				s++;
			}
			else goto _tryagainc1;
		}
		for (; x < mkpwa->length; x++) {
_tryagainc2:		c = (char)tf_prng_range_r(rndata, 0x20, 0x7f);
			if (strchr(MKPWD_DIGIT_STRING, c)) {
				*s = c;
				s++;
			}
			else goto _tryagainc2;
		}

		s = ret; d = bpw;
		for (x = 0; x < mkpwa->length; x++) {
_tryagainc3:		i = (size_t)tf_prng_range_r(rndata, 0, (TF_UNIT_TYPE)mkpwa->length-1);
			if (d[i] == '\0') goto _tryagainc3;
			*s = d[i];
			s++;
			d[i] = '\0';
		}

		tf_prng_seedkey_r(rndata, NULL);
		genpwd_free(rndata);
		goto _ret;
	}
	else if (mkpwa->format == MKPWD_FMT_UNIV) {
		void *rndata;
		char c, *s = ret;
		size_t x;

		if (mkpwa->charstart == '\0') mkpwa->charstart = 0x20;
		if (mkpwa->charend == '\0') mkpwa->charend = 0x7f;

		bpw = genpwd_realloc(bpw, TF_KEY_SIZE);
		rndata = genpwd_malloc(tf_prng_datasize());

		tf_prng_seedkey_r(rndata, bpw);

		for (x = 0; x < mkpwa->length; x++) {
_tryagainu:		c = (char)tf_prng_range_r(rndata, (TF_UNIT_TYPE)mkpwa->charstart, (TF_UNIT_TYPE)mkpwa->charend);
			if (mkpwa->charset) {
				if (strchr(mkpwa->charset, c)) {
					*s = c;
					s++;
				}
				else goto _tryagainu;
			}
			else {
				*s = c;
				s++;
			}
		}

		tf_prng_seedkey_r(rndata, NULL);
		genpwd_free(rndata);
		goto _ret;
	}
	else reterror(NULL, "Unsupported mkpwd format");

	uret = ret;
	memmove(ret, uret+mkpwa->offset, mkpwa->length);
	memset(uret+mkpwa->length, 0, mkpwa->pwdmax - mkpwa->length);

_ret:	genpwd_free(bpw);
	uret = ret;
	mkpwa->szresult = strnlen(uret, mkpwa->pwdmax);
	ret = genpwd_realloc(ret, mkpwa->szresult+1);
	mkpwa->result = ret;
	mkpwa->error = NULL;
	return MKPWD_YES;
}
#undef reterror

int mkpwd_key(struct mkpwd_args *mkpwa)
{
	struct skein sk;
	size_t x;
	void *ret;

	if (!mkpwa) return MKPWD_NO;
	init_mkpwa(mkpwa);
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)
	|| !mkpwa->id) return MKPWD_NO;

	ret = genpwd_malloc(mkpwa->length);

	skein_init(&sk, TF_TO_BITS(mkpwa->length));
	skein_update(&sk, mkpwa->pwd, mkpwa->szpwd ? mkpwa->szpwd : strnlen(mkpwa->pwd, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt ? mkpwa->szsalt : strnlen(mkpwa->salt, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->id, mkpwa->szid ? mkpwa->szid : strnlen(mkpwa->id, mkpwa->pwdmax));
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
	init_mkpwa(mkpwa);
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)) return MKPWD_NO;

	bpw = ubpw = genpwd_malloc(TF_FROM_BITS(16));
	ret = genpwd_malloc(8);

	skein_init(&sk, 16);
	skein_update(&sk, mkpwa->pwd, mkpwa->szpwd ? mkpwa->szpwd : strnlen(mkpwa->pwd, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt ? mkpwa->szsalt : strnlen(mkpwa->salt, mkpwa->pwdmax));
	skein_final(bpw, &sk);

	snprintf(ret, 8, "%02hhx%02hhx", ubpw[0], ubpw[1]);

	genpwd_free(bpw);
	mkpwa->result = ret;
	mkpwa->szresult = 4;
	mkpwa->error = NULL;
	return MKPWD_YES;
}

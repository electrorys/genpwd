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

int mkpwd(struct mkpwd_args *mkpwa)
{
	struct skein sk;
	void *r, *bpw, *rndata;
	char *ur;
	size_t x;

	if (!mkpwa) return MKPWD_NO;
	init_mkpwa(mkpwa);
	if (!mkpwa->pwd
	|| !mkpwa->salt
	|| !mkpwa->id
	|| mkpwa->length == 0
	|| mkpwa->length >= mkpwa->pwdmax) return MKPWD_NO;

	bpw = genpwd_malloc(SKEIN_DIGEST_SIZE);
	r = genpwd_malloc(mkpwa->pwdmax);

	skein_init(&sk, TF_MAX_BITS);
	skein_update(&sk, mkpwa->pwd, mkpwa->szpwd ? mkpwa->szpwd : strnlen(mkpwa->pwd, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt ? mkpwa->szsalt : strnlen(mkpwa->salt, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->id, mkpwa->szid ? mkpwa->szid : strnlen(mkpwa->id, mkpwa->pwdmax));
	skein_final(bpw, &sk);

	if (mkpwa->turns > 0) {
		for (x = 0; x < mkpwa->turns; x++)
			skein(bpw, TF_MAX_BITS, bpw, SKEIN_DIGEST_SIZE);
	}

	if (mkpwa->format == MKPWD_FMT_B64) {
		base64_encode(r, bpw, TF_KEY_SIZE);
		remove_chars(r, mkpwa->pwdmax, "./+=");
	}
	else if (mkpwa->format == MKPWD_FMT_CPWD) {
		char c, *s, *d;
		size_t x, i;

		bpw = genpwd_realloc(bpw, mkpwa->length > TF_KEY_SIZE ? mkpwa->length : TF_KEY_SIZE);
		rndata = genpwd_malloc(tf_prng_datasize());

		tf_prng_seedkey_r(rndata, bpw);

		s = bpw;
		for (x = 0; x < mkpwa->length/2; x++) {
_tryagainc1:		c = (char)tf_prng_range_r(rndata, (TF_UNIT_TYPE)0x20, (TF_UNIT_TYPE)0x7f);
			if (strchr(MKPWD_ALPHA_STRING, c)) {
				*s = c;
				s++;
			}
			else goto _tryagainc1;
		}
		for (; x < mkpwa->length; x++) {
_tryagainc2:		c = (char)tf_prng_range_r(rndata, (TF_UNIT_TYPE)0x20, (TF_UNIT_TYPE)0x7f);
			if (strchr(MKPWD_DIGIT_STRING, c)) {
				*s = c;
				s++;
			}
			else goto _tryagainc2;
		}

		s = r; d = bpw;
		for (x = 0; x < mkpwa->length; x++) {
_tryagainc3:		i = (size_t)tf_prng_range_r(rndata, (TF_UNIT_TYPE)0, (TF_UNIT_TYPE)mkpwa->length-1);
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
		char c, *s;
		size_t x;
		unsigned char S, E;

		bpw = genpwd_realloc(bpw, TF_KEY_SIZE);
		rndata = genpwd_malloc(tf_prng_datasize());

		tf_prng_seedkey_r(rndata, bpw);

		if (!mkpwa->charset) {
			S = 0x20;
			E = 0x7f;
		}
		else {
			S = 1;
			E = (unsigned char)UCHAR_MAX;
		}

		for (x = 0, s = r; x < mkpwa->length; x++) {
_tryagainu:		c = (char)tf_prng_range_r(rndata, (TF_UNIT_TYPE)S, (TF_UNIT_TYPE)E);
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
	else {
		genpwd_free(bpw);
		genpwd_free(r);
		mkpwa->result = NULL;
		mkpwa->szresult = 0;
		return MKPWD_NO;
	}

	ur = r;
	memmove(r, ur+mkpwa->offset, mkpwa->length);
	memset(ur+mkpwa->length, 0, mkpwa->pwdmax - mkpwa->length);

_ret:	genpwd_free(bpw);
	ur = r;
	mkpwa->szresult = strnlen(ur, mkpwa->pwdmax);
	r = genpwd_realloc(r, mkpwa->szresult+1);
	mkpwa->result = r;
	return MKPWD_YES;
}

int mkpwd_key(struct mkpwd_args *mkpwa)
{
	struct skein sk;
	size_t x;
	void *r;

	if (!mkpwa) return MKPWD_NO;
	init_mkpwa(mkpwa);
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)
	|| !mkpwa->id) return MKPWD_NO;

	r = genpwd_malloc(mkpwa->length);

	skein_init(&sk, TF_TO_BITS(mkpwa->length));
	skein_update(&sk, mkpwa->pwd, mkpwa->szpwd ? mkpwa->szpwd : strnlen(mkpwa->pwd, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt ? mkpwa->szsalt : strnlen(mkpwa->salt, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->id, mkpwa->szid ? mkpwa->szid : strnlen(mkpwa->id, mkpwa->pwdmax));
	skein_final(r, &sk);

	if (mkpwa->turns) {
		for (x = 0; x < mkpwa->turns; x++)
			skein(r, TF_TO_BITS(mkpwa->length), r, mkpwa->length);
	}

	mkpwa->result = r;
	mkpwa->szresult = mkpwa->length;
	return MKPWD_YES;
}

int mkpwd_hint(struct mkpwd_args *mkpwa)
{
	struct skein sk;
	void *bpw, *r;
	char *ubpw;

	if (!mkpwa) return MKPWD_NO;
	init_mkpwa(mkpwa);
	if (!mkpwa->pwd
	|| (!mkpwa->salt || mkpwa->szsalt == 0)) return MKPWD_NO;

	bpw = ubpw = genpwd_malloc(TF_FROM_BITS(16));
	r = genpwd_malloc(8);

	skein_init(&sk, 16);
	skein_update(&sk, mkpwa->pwd, mkpwa->szpwd ? mkpwa->szpwd : strnlen(mkpwa->pwd, mkpwa->pwdmax));
	skein_update(&sk, mkpwa->salt, mkpwa->szsalt ? mkpwa->szsalt : strnlen(mkpwa->salt, mkpwa->pwdmax));
	skein_final(bpw, &sk);

	snprintf(r, 8, "%02hhx%02hhx", ubpw[0], ubpw[1]);

	genpwd_free(bpw);
	mkpwa->result = r;
	mkpwa->szresult = 4;
	return MKPWD_YES;
}

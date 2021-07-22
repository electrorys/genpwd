/*
 * MIT License
 *
 * Copyright (c) 2021 Andrey Rys
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#include "genpwd.h"

void genpwd_read_defaults(const char *path, gpwd_yesno noerr)
{
	static char ln[4096];
	char *s, *d, *t, *stoi;
	FILE *f;
	gpwd_yesno valid = NO;

	f = fopen(path, "r");
	if (!f) {
		if (noerr == YES) return;
		xerror(NO, NO, "%s", path);
	}

	while (1) {
		memset(ln, 0, sizeof(ln));
		if (genpwd_fgets(ln, sizeof(ln), f) != YES) break;

		if (valid == NO) {
			if (!strcmp(ln, "# genpwd.defs")) valid = YES;
			continue;
		}

		if (str_empty(ln) || is_comment(ln)) continue;

		s = ln;
		d = strchr(s, '=');
		if (!d) continue;
		*d = 0; d++;

		/* yay! GOTO hell! You'll "like" it! */
_spc1:		t = strchr(s, ' ');
		if (!t) goto _spc2;
		*t = 0; goto _spc1;
_spc2:		t = strchr(d, ' ');
		if (!t) goto _nspc;
		*t = 0; d = t+1; goto _spc2;
_nspc:
		if (!strcmp(s, "default_turns_number")) {
			default_turns_number = strtoul(d, &stoi, 10);
			if (!str_empty(stoi)) xerror(NO, YES, "[%s] %s: invalid turns number", path, d);
		}
		else if (!strcmp(s, "default_string_offset")) {
			default_string_offset = strtoul(d, &stoi, 10);
			if (!str_empty(stoi)) xerror(NO, YES, "[%s] %s: invalid offset number", path, d);
		}
		else if (!strcmp(s, "default_password_length")) {
			default_password_length = strtoul(d, &stoi, 10);
			if (!str_empty(stoi) || default_password_length == 0) xerror(NO, YES, "[%s] %s: invalid password length number", path, d);
		}
		else if (!strcmp(s, "default_password_format")) {
			if (!strcasecmp(d, CPPSTR(MKPWD_FMT_B64)) || !strcasecmp(d, "default")) default_password_format = MKPWD_FMT_B64;
			else if (!strcasecmp(d, CPPSTR(MKPWD_FMT_CPWD)) || !strcasecmp(d, "C")) default_password_format = MKPWD_FMT_CPWD;
			else if (!strcasecmp(d, CPPSTR(MKPWD_FMT_UNIV)) || !strcasecmp(d, "U")) {
				default_password_format = MKPWD_FMT_UNIV;
				genpwd_free(default_password_charset);
				default_password_charset = genpwd_strdup(GENPWD_ALNUM_STRING);
			}
		}
		else if (!strcmp(s, "default_password_charset")) {
			default_password_format = MKPWD_FMT_UNIV;
			genpwd_free(default_password_charset);
			if (!strcmp(d, GENPWD_ALNUM_STRING_NAME)) d = GENPWD_ALNUM_STRING;
			else if (!strcmp(d, GENPWD_ALPHA_STRING_NAME)) d = GENPWD_ALPHA_STRING;
			else if (!strcmp(d, GENPWD_LOWER_STRING_NAME)) d = GENPWD_LOWER_STRING;
			else if (!strcmp(d, GENPWD_UPPER_STRING_NAME)) d = GENPWD_UPPER_STRING;
			else if (!strcmp(d, GENPWD_DIGIT_STRING_NAME)) d = GENPWD_DIGIT_STRING;
			else if (!strcmp(d, GENPWD_XDIGIT_STRING_NAME)) d = GENPWD_XDIGIT_STRING;
			else if (!strcmp(d, GENPWD_UXDIGIT_STRING_NAME)) d = GENPWD_UXDIGIT_STRING;
			else if (!strcmp(d, GENPWD_ASCII_STRING_NAME)) d = GENPWD_ASCII_STRING;
			default_password_charset = genpwd_strdup(d);
		}
		else if (!strcmp(s, "genpwd_save_ids")) {
			if (!strcasecmp(d, "yes") || !strcmp(d, "1")) genpwd_save_ids = YES;
			else if (!strcasecmp(d, "no") || !strcmp(d, "0")) genpwd_save_ids = NO;
		}
		else if (!strcmp(s, "genpwd_salt")) {
			memset(genpwd_salt, 0, GENPWD_MAX_SALT);
			genpwd_szsalt = base64_decode((char *)genpwd_salt, GENPWD_MAX_SALT, d, strlen(d));
		}
		else xerror(NO, YES, "[%s] %s: unknown keyword", path, s);
	}

	memset(ln, 0, sizeof(ln));
	fclose(f);
}

void genpwd_hash_defaults(char *uhash, size_t szuhash)
{
	struct skein sk;
	gpwd_byte hash[TF_FROM_BITS(256)];
	char shash[56];

	skein_init(&sk, 256);

	skein_update(&sk, genpwd_salt, genpwd_szsalt);

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%zu", default_turns_number);
	skein_update(&sk, shash, strlen(shash));

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%zu", default_string_offset);
	skein_update(&sk, shash, strlen(shash));

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%zu", default_password_length);
	skein_update(&sk, shash, strlen(shash));

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%hd", default_password_format);
	skein_update(&sk, shash, strlen(shash));

	if (default_password_charset) skein_update(&sk, default_password_charset, strlen(default_password_charset));

	skein_final(hash, &sk);
	memset(shash, 0, sizeof(shash));
	base64_encode(shash, (const char *)hash, sizeof(hash));
	memset(hash, 0, sizeof(hash));

	xstrlcpy(uhash, shash, szuhash);
}

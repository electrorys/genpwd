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

const char *pwl_charset_name(const char *charset)
{
	if (!charset) return default_password_charset;

	if (!strcmp(charset, GENPWD_ALNUM_STRING)) return GENPWD_ALNUM_STRING_NAME;
	else if (!strcmp(charset, GENPWD_ALPHA_STRING)) return GENPWD_ALPHA_STRING_NAME;
	else if (!strcmp(charset, GENPWD_LOWER_STRING)) return GENPWD_LOWER_STRING_NAME;
	else if (!strcmp(charset, GENPWD_UPPER_STRING)) return GENPWD_UPPER_STRING_NAME;
	else if (!strcmp(charset, GENPWD_DIGIT_STRING)) return GENPWD_DIGIT_STRING_NAME;
	else if (!strcmp(charset, GENPWD_XDIGIT_STRING)) return GENPWD_XDIGIT_STRING_NAME;
	else if (!strcmp(charset, GENPWD_UXDIGIT_STRING)) return GENPWD_UXDIGIT_STRING_NAME;
	else if (!strcmp(charset, GENPWD_ASCII_STRING)) return GENPWD_ASCII_STRING_NAME;

	return charset;
}

const char *pwl_charset_string(const char *csname)
{
	if (!csname) return GENPWD_ALNUM_STRING;

	if (!strcmp(csname, GENPWD_ALNUM_STRING_NAME)) return GENPWD_ALNUM_STRING;
	else if (!strcmp(csname, GENPWD_ALPHA_STRING_NAME)) return GENPWD_ALPHA_STRING;
	else if (!strcmp(csname, GENPWD_LOWER_STRING_NAME)) return GENPWD_LOWER_STRING;
	else if (!strcmp(csname, GENPWD_UPPER_STRING_NAME)) return GENPWD_UPPER_STRING;
	else if (!strcmp(csname, GENPWD_DIGIT_STRING_NAME)) return GENPWD_DIGIT_STRING;
	else if (!strcmp(csname, GENPWD_XDIGIT_STRING_NAME)) return GENPWD_XDIGIT_STRING;
	else if (!strcmp(csname, GENPWD_UXDIGIT_STRING_NAME)) return GENPWD_UXDIGIT_STRING;
	else if (!strcmp(csname, GENPWD_ASCII_STRING_NAME)) return GENPWD_ASCII_STRING;

	return csname;
}

void mkpwd_adjust(struct mkpwd_args *mkpwa)
{
	mkpwa->pwdmax = GENPWD_PWD_MAX;
	mkpwa->salt = genpwd_salt;
	mkpwa->szsalt = genpwd_szsalt;
	mkpwa->turns = default_turns_number;
	mkpwa->offset = default_string_offset;
	mkpwa->length = default_password_length;
	mkpwa->format = default_password_format;
	if (default_password_charset) mkpwa->charset = default_password_charset;
}

gpwd_yesno is_comment(const char *str)
{
	if (str_empty(str)
	|| *str == '#'
	|| *str == '\n'
	|| (*str == '\r' && *(str+1) == '\n')) return YES;
	return NO;
}

gpwd_yesno str_empty(const char *str)
{
	if (!*str) return YES;
	return NO;
}

static void char_to_nul(char *s, size_t l, int c)
{
	while (*s && l) { if (*s == c) { *s = 0; break; } s++; l--; }
}

gpwd_yesno genpwd_fgets(char *s, size_t n, FILE *f)
{
	memset(s, 0, n);

	if (fgets(s, (int)n, f) == s) {
		char_to_nul(s, n, '\n');
		return YES;
	}

	return NO;
}

off_t genpwd_fdsize(int fd)
{
	off_t l, cur;

	cur = lseek(fd, 0L, SEEK_CUR);
	l = lseek(fd, 0L, SEEK_SET);
	if (l == -1) return -1;
	l = lseek(fd, 0L, SEEK_END);
	if (l == -1) return -1;
	lseek(fd, cur, SEEK_SET);
	return l;
}

void *genpwd_read_alloc_fd(int fd, size_t blksz, size_t max, size_t *rsz)
{
	void *ret;
	size_t sz, xsz, cur;

	if (blksz == 0 || !rsz) return NULL;

	if (max) sz = xsz = max;
	else sz = xsz = (size_t)genpwd_fdsize(fd);
	if (sz == NOSIZE) return NULL;
	cur = (size_t)lseek(fd, 0L, SEEK_CUR);
	if (cur == NOSIZE) return NULL;
	if (cur) {
		if (cur >= xsz) return NULL;
		xsz -= cur;
		sz = xsz;
	}

	ret = genpwd_malloc(sz);
	if (sz >= blksz) {
		do {
			if (read(fd, ret+(xsz-sz), blksz) == NOSIZE) goto _err;
		} while ((sz -= blksz) >= blksz);
	}
	if (sz) {
		if (read(fd, ret+(xsz-sz), blksz) == NOSIZE) goto _err;
	}

	*rsz = xsz;
	return ret;

_err:
	genpwd_free(ret);
	*rsz = (xsz-sz);
	return NULL;
}

void *genpwd_read_alloc_file(const char *file, size_t *rsz)
{
	int fd;
	void *r;

	fd = open(file, O_RDONLY);
	if (fd == -1) xerror(0, 0, "%s", file);
	r = genpwd_read_alloc_fd(fd, GENPWD_PWD_MAX, 0, rsz);
	close(fd);
	return r;
}

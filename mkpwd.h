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

#ifndef _MKPWD_H
#define _MKPWD_H

#define MKPWD_NO	0
#define MKPWD_YES	1

#define MKPWD_FMT_B64	0
#define MKPWD_FMT_UNIV	1
#define MKPWD_FMT_CPWD	2

#define MKPWD_ALPHA_STRING "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define MKPWD_DIGIT_STRING "0123456789"

struct mkpwd_args {
	size_t pwdmax;

	const char *pwd;
	size_t szpwd;
	const char *id;
	size_t szid;
	const void *salt;
	size_t szsalt;

	short format;
	char *charset, cs, ce;
	size_t turns;
	size_t offset;
	size_t length;

	void *result;
	size_t szresult;
};

int mkpwd(struct mkpwd_args *mkpwa);
int mkpwd_key(struct mkpwd_args *mkpwa);
int mkpwd_hint(struct mkpwd_args *mkpwa);

#endif

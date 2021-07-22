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

void genpwd_vfsay(FILE *where, int addnl, const char *fmt, va_list ap)
{
	va_list t;

	if (!strcmp(fmt, "\n")) {
		fputc('\n', where);
		return;
	}

	va_copy(t, ap);
	vfprintf(where, fmt, t);
	va_end(t);
	if (addnl) fputc('\n', where);
	fflush(where);
}

void genpwd_nvesay(const char *fmt, va_list ap)
{
	va_list t;

	va_copy(t, ap);
	genpwd_vfsay(stderr, 0, fmt, t);
	va_end(t);
}

void genpwd_nesay(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	genpwd_vfsay(stderr, 0, fmt, ap);
	va_end(ap);
}

void genpwd_nsay(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	genpwd_vfsay(stdout, 0, fmt, ap);
	va_end(ap);
}

void genpwd_esay(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	genpwd_vfsay(stderr, 1, fmt, ap);
	va_end(ap);
}

void genpwd_say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	genpwd_vfsay(stdout, 1, fmt, ap);
	va_end(ap);
}

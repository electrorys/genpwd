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

void genpwd_exit(int status)
{
	genpwd_finirandom();
	genpwd_exit_memory();
	exit(status);
}

void signal_handler(int sig)
{
	genpwd_esay("%s: got signal %d.", progname, sig);
	genpwd_exit(sig);
}

void install_signals(void)
{
	int x;
	for (x = 1; x < NSIG; x++) signal(x, signal_handler);
}

void xerror(gpwd_yesno noexit, gpwd_yesno noerrno, const char *fmt, ...)
{
	va_list ap;
	char *s;

	genpwd_nesay("%s: ", progname);
	va_start(ap, fmt);
	genpwd_nvesay(fmt, ap);
	va_end(ap);
	if (errno && !noerrno) {
		s = strerror(errno);
		genpwd_esay(": %s", s);
	}
	else genpwd_esay("\n");

	if (noexit) {
		errno = 0;
		return;
	}

	genpwd_exit(2);
}

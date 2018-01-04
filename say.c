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

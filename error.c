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

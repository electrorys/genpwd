#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "getpasswd.h"

size_t getpasswd(struct getpasswd_state *getps)
{
	int fd, tty_opened = 0, x;
	int c, clear;
	struct termios s, t;
	size_t l;

	if (!getps) return ((size_t)-1);

	if (getps->fd == -1) {
		if ((fd = open("/dev/tty", O_RDONLY|O_NOCTTY)) < 0) fd = 0;
		getps->fd = fd;
		tty_opened = 1;
	}
	else fd = getps->fd;

	memset(&t, 0, sizeof(struct termios));
	memset(&s, 0, sizeof(struct termios));
	tcgetattr(fd, &t);
	s = t;
	if (getps->sanetty) memcpy(getps->sanetty, &s, sizeof(struct termios));
	cfmakeraw(&t);
	t.c_iflag |= ICRNL;
	tcsetattr(fd, TCSANOW, &t);

	if (getps->echo) {
		fputs(getps->echo, stderr);
		fflush(stderr);
	}

	l = 0; x = 0;
	while (1) {
		clear = 1;
		c = 0;
		if (read(fd, &c, sizeof(char)) == -1) break;
		if (getps->charfilter) {
			x = getps->charfilter(getps, c, l);
			if (x == 0) {
				clear = 0;
				goto _newl;
			}
			else if (x == 2) continue;
			else if (x == 3) goto _erase;
			else if (x == 4) goto _delete;
			else if (x == 5) break;
			else if (x == 6) {
				clear = 0;
				l = getps->retn;
				memset(getps->passwd, 0, getps->pwlen);
				goto _err;
			}
		}

		if (c == '\x7f'
		|| (c == '\x08' && !(getps->flags & GETP_NOINTERP))) { /* Backspace / ^H */
_erase:			if (l == 0) continue;
			clear = 0;
			l--;
			if (!(getps->flags & GETP_NOECHO)) fputs("\x08\e[1X", stderr);
			fflush(stderr);
		}
		else if (!(getps->flags & GETP_NOINTERP)
		&& (c == '\x15' || c == '\x17')) { /* ^U / ^W */
_delete:		clear = 0;
			l = 0;
			memset(getps->passwd, 0, getps->pwlen);
			fputs("\e[2K\e[0G", stderr);
			if (getps->echo) fputs(getps->echo, stderr);
			fflush(stderr);
		}
_newl:		if (c == '\n' || c == '\r' || (!(getps->flags & GETP_NOINTERP) && c == '\x04')) break;
		if (clear) {
			*(getps->passwd+l) = c;
			l++;
			if (!(getps->flags & GETP_NOECHO)) fputc(getps->maskchar, stderr);
			fflush(stderr);
		}
		if (l >= getps->pwlen) break;
	};

_err:	fputs("\r\n", stderr);
	fflush(stderr);
	if (x != 6) *(getps->passwd+l) = 0;

	tcsetattr(fd, TCSANOW, &s);

	if (tty_opened) close(fd);

	return l;
}

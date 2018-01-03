#include "genpwd.h"

void genpwd_getrandom(void *buf, size_t size)
{
	char *ubuf = buf;
	int fd = -1;
	size_t rd;
	int x;

	/* Most common and probably available on every Nix, */
	fd = open("/dev/urandom", O_RDONLY);
	/* OpenBSD arc4 */
	if (fd == -1) fd = open("/dev/arandom", O_RDONLY);
	/* OpenBSD simple urandom */
	if (fd == -1) fd = open("/dev/prandom", O_RDONLY);
	/* OpenBSD srandom, blocking! */
	if (fd == -1) fd = open("/dev/srandom", O_RDONLY);
	/* Most common blocking. */
	if (fd == -1) fd = open("/dev/random", O_RDONLY);
	/* Very bad, is this a crippled chroot? */
	if (fd == -1) xerror(0, 1, "urandom is required");

	x = 0;
_again:	rd = read(fd, ubuf, size);
	/* I want full random block, and there is no EOF can be! */
	if (rd < size) {
		if (x >= 100) xerror(0, 1, "urandom always returns less bytes! (rd = %zu)", rd);
		x++;
		ubuf += rd;
		size -= rd;
		goto _again;
	}

	close(fd);
}

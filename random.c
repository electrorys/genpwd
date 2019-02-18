#include "genpwd.h"

static void get_urandom(void *buf, size_t size)
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

static int genpwd_random_initialised;

static void genpwd_initrandom(void)
{
	unsigned char k[TF_KEY_SIZE];

	if (genpwd_random_initialised == 1) return;

	get_urandom(k, TF_KEY_SIZE);
	tf_prng_seedkey(k);
	memset(k, 0, TF_KEY_SIZE);

	genpwd_random_initialised = 1;
}

void genpwd_finirandom(void)
{
	tf_prng_seedkey(NULL);
	genpwd_random_initialised = 0;
}

void genpwd_getrandom(void *buf, size_t sz)
{
	if (genpwd_random_initialised == 0) genpwd_initrandom();
	tf_prng_genrandom(buf, sz);
}
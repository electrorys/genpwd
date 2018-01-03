#include "genpwd.h"

const unsigned char *loaded_salt = salt;

void sk1024iter(const unsigned char *src, size_t len, unsigned char *digest, unsigned int bits, unsigned int passes)
{
	unsigned char dgst[128] = {0};
	int x;

	if (passes == 0)
		return;

	sk1024(src, len, dgst, bits);
	for (x = 0; x < passes-1; x++)
		sk1024(dgst, bits/8, dgst, bits);

	memmove(digest, dgst, bits/8);
	memset(dgst, 0, sizeof(dgst));
}

void mkpwd_adjust(struct mkpwd_args *mkpwa)
{
	mkpwa->passes = default_passes_number;
	mkpwa->offset = default_string_offset;
	mkpwa->length = default_password_length;
}

off_t fdsize(int fd)
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

void *read_alloc_fd(int fd, size_t blksz, size_t max, size_t *rsz)
{
	void *ret;
	size_t sz, xsz, cur;

	if (blksz == 0 || !rsz) return NULL;

	if (max) sz = xsz = max;
	else sz = xsz = (size_t)fdsize(fd);
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

void *read_alloc_file(const char *file, size_t *rsz)
{
	int fd;
	void *r;

	fd = open(file, O_RDONLY);
	if (fd == -1) xerror(0, 0, "%s", file);
	r = read_alloc_fd(fd, 256, 0, rsz);
	close(fd);
	return r;
}

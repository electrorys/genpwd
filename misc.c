#include "genpwd.h"

void mkpwd_adjust(struct mkpwd_args *mkpwa)
{
	mkpwa->passes = default_passes_number;
	mkpwa->offset = default_string_offset;
	mkpwa->length = default_password_length;
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
	r = genpwd_read_alloc_fd(fd, GENPWD_MAXPWD, 0, rsz);
	close(fd);
	return r;
}

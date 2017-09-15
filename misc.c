#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <errno.h>

#include "genpwd.h"
#include "tf1024.h"
#include "smalloc.h"

static char genpwd_memory_pool[65536];

char **ids;
int nids;
static int need_to_save_ids;

static char *data = NULL;
static size_t dsz = 0;

const unsigned char *_salt = salt;
extern size_t _slen;

static size_t genpwd_oom_handler(struct smalloc_pool *spool, size_t failsz)
{
	xerror(0, 1, "OOM: failed to allocate %zu bytes!", failsz);
	return 0;
}

static void genpwd_ub_handler(struct smalloc_pool *spool, const void *offender)
{
	xerror(0, 1, "UB: %p is not from our data storage!", offender);
}

static int genpwd_memory_initialised;

void genpwd_init_memory(void)
{
	if (!genpwd_memory_initialised) {
		sm_set_ub_handler(genpwd_ub_handler);
		if (!sm_set_default_pool(
		genpwd_memory_pool, sizeof(genpwd_memory_pool), 1, genpwd_oom_handler))
			xerror(0, 1, "memory pool initialisation failed!");
		genpwd_memory_initialised = 1;
	}
}

void genpwd_exit_memory(void)
{
	/* will erase memory pool automatically */
	sm_release_default_pool();
	genpwd_memory_initialised = 0;
}

void genpwd_free(void *p)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	sm_free(p);
}

void *genpwd_malloc(size_t sz)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	return sm_malloc(sz);
}

void *genpwd_calloc(size_t nm, size_t sz)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	return sm_calloc(nm, sz);
}

void *genpwd_realloc(void *p, size_t newsz)
{
	if (!genpwd_memory_initialised) genpwd_init_memory();
	return sm_realloc(p, newsz);
}

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

void xerror(int noexit, int noerrno, const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);

	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	if (errno && !noerrno) {
		s = strerror(errno);
		fprintf(stderr, ": %s\n", s);
	}
	else fputc('\n', stderr);

	va_end(ap);

	if (noexit) {
		errno = 0;
		return;
	}

	exit(2);
}

void daemonise(void)
{
#ifdef DAEMONISE
	pid_t pid, sid;
	int i;

	pid = fork();
	if (pid < 0)
		exit(-1);
	if (pid > 0)
		exit(0);

	sid = setsid();
	if (sid < 0)
		exit(-1);

	close(0);
	close(1);
	close(2);
	for (i = 0; i < 3; i++)
		open("/dev/null", O_RDWR);
#else
	return;
#endif
}


int iscomment(const char *s)
{
	if (!*s
	|| *s == '#'
	|| *s == '\n'
	|| (*s == '\r' && *(s+1) == '\n')) return 1;
	return 0;
}

void to_saveids(int x)
{
	if (need_to_save_ids == -1) return;
	need_to_save_ids = x;
}

int findid(const char *id)
{
	int x;

	for (x = 0; x < nids; x++) {
		if (*(ids+x)
		&& !strcmp(*(ids+x), id)) return x;
	}

	return -1;
}

int delid(const char *id)
{
	int idx;
	size_t n;

	if (!id) return 0;

	idx = findid(id);
	if (idx == -1) return 0;

	if (*(ids+idx)) {
		n = strlen(*(ids+idx));
		memset(*(ids+idx), 0, n);
		*(ids+idx) = NULL;
		return 1;
	}

	return 0;
}

int is_dupid(const char *id)
{

	if (iscomment(id)) return 0;
	if (findid(id) > -1) return 1;

	return 0;
}

static void addid_init(const char *id, char *initid)
{
	size_t n;
	char *old;
	int x;

	if ((id && iscomment(id)) || (initid && iscomment(initid))) return;

	ids = genpwd_realloc(ids, sizeof(char *) * (nids + 1));
	if (!ids) to_saveids(-1);

	if (!initid) {
		n = strlen(id);
		old = data;
		data = genpwd_realloc(data, dsz+n+1);
		if (!data) to_saveids(-1);
		if (data != old) {
			for (x = 0; x < nids; x++) {
				if (*(ids+x))
					*(ids+x) -= (old-data);
			}
		}
		memset(data+dsz, 0, n+1);
		xstrlcpy(data+dsz, id, n+1);
		*(ids+nids) = data+dsz;
		dsz += n+1;
	}
	else *(ids+nids) = initid;

	nids++;
}

void addid(const char *id)
{
	addid_init(id, NULL);
}

void sk1024_loop(const unsigned char *src, size_t len, unsigned char *digest,
			unsigned int bits, unsigned int passes)
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

void mkpwd_adjust(void)
{
	mkpwd_passes_number = default_passes_number;
	mkpwd_string_offset = default_string_offset;
	mkpwd_password_length = default_password_length;
}

static void prepare_context(tf1024_ctx *tctx, const void *ctr)
{
	unsigned char key[TF_KEY_SIZE], tweak[sizeof(tctx->tfc.T)-TF_SIZE_UNIT];

	mkpwd_adjust();

	sk1024(_salt, _slen, key, TF_MAX_BITS);
	if (mkpwd_passes_number > 1)
		sk1024_loop(key, TF_KEY_SIZE, key, TF_MAX_BITS, mkpwd_passes_number);
	tf1024_init(tctx);
	tfc1024_set_key(&tctx->tfc, key, TF_KEY_SIZE);
	sk1024(key, sizeof(key), tweak, TF_TO_BITS(sizeof(tweak)));
	tfc1024_set_tweak(&tctx->tfc, tweak);
	tf1024_start_counter(tctx, ctr);

	memset(tweak, 0, sizeof(tweak));
	memset(key, 0, TF_KEY_SIZE);
}

static off_t fdsize(int fd)
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

static int decrypt_ids(FILE *f, char **data, size_t *dsz)
{
	char *ret = NULL; size_t n;
	tf1024_ctx tctx;
	unsigned char ctr[TF_KEY_SIZE];

	n = (size_t)fdsize(fileno(f));
	if (n == ((size_t)-1))
		goto err;

	if (n <= sizeof(ctr))
		goto err;
	n -= sizeof(ctr);

	ret = genpwd_malloc(n+1);
	if (!ret) goto err;

	if (fread(ctr, sizeof(ctr), 1, f) < 1) goto err;
	prepare_context(&tctx, ctr);
	memset(ctr, 0, sizeof(ctr));

	if (fread(ret, n, 1, f) < 1) goto err;
	/* check this before decrypt data + MAC checksum */
	if (n <= sizeof(ctr))
		goto err;
	tf1024_crypt(&tctx, ret, n-sizeof(ctr), ret);

	/* check MAC checksum at end of file (tfcrypt compatible) */
	if (n <= sizeof(ctr))
		goto err;
	n -= sizeof(ctr);
	tf1024_crypt(&tctx, ret+n, sizeof(ctr), ret+n);
	sk1024(ret, n, ctr, TF_MAX_BITS);
	if (memcmp(ret+n, ctr, sizeof(ctr)) != 0)
		goto err;
	memset(ctr, 0, sizeof(ctr));
	memset(ret+n, 0, sizeof(ctr));

	if (strncmp(ret, genpwd_ids_magic, sizeof(genpwd_ids_magic)-1) != 0)
		goto err;

	tf1024_done(&tctx);
	*data = ret; *dsz = n;

	return 1;

err:
	memset(ctr, 0, sizeof(ctr));
	tf1024_done(&tctx);
	if (ret) {
		memset(ret, 0, n);
		genpwd_free(ret);
	}
	*data = NULL;
	*dsz = 0;
	return 0;
}

static void encrypt_ids(FILE *f, char *data, size_t dsz)
{
	tf1024_ctx tctx;
	unsigned char ctr[TF_KEY_SIZE];

	genpwd_getrandom(ctr, sizeof(ctr));
	fwrite(ctr, sizeof(ctr), 1, f);
	prepare_context(&tctx, ctr);
	memset(ctr, 0, sizeof(ctr));

	/* data maybe even shorter - see when ids file does not exist. */
	sk1024(data, dsz, ctr, TF_MAX_BITS);
	tf1024_crypt(&tctx, data, dsz, data);
	tf1024_crypt(&tctx, ctr, sizeof(ctr), ctr);

	/* write counter + data */
	fwrite(data, dsz, 1, f);
	/* write MAC checksum */
	fwrite(ctr, sizeof(ctr), 1, f);

	memset(ctr, 0, sizeof(ctr));
	tf1024_done(&tctx);
}

static void remove_deadids(char *data, size_t *n)
{
	char *s, *d, *t;
	char dmy[2];

	dmy[0] = 0; dmy[1] = 0;

	s = d = data;
	while (s && s-data < *n) {
		d = memmem(s, *n-(s-data), dmy, 2);
		if (!d) break;
		t = d+1;
		while (d-data < *n && !*d) d++;
		if (d-data >= *n)
			s = NULL;
		else memmove(t, d, *n-(d-data));
		*n -= (d-t);
	}
}

static void alloc_fheader(void)
{
	if (data && dsz) return;

	data = genpwd_malloc(sizeof(genpwd_ids_magic));
	memcpy(data, genpwd_ids_magic, sizeof(genpwd_ids_magic));
	dsz = sizeof(genpwd_ids_magic);
}

void loadids(ids_populate_fn idpfn)
{
	char path[PATH_MAX];
	FILE *f = NULL;
	char *s, *d, *t;
	int x;

	s = getenv("HOME");
	if (!s) return;

	ids = genpwd_malloc(sizeof(char *));
	if (!ids) return;

	memset(path, 0, sizeof(path));
	snprintf(path, PATH_MAX-1, "%s/%s", s, genpwd_ids_fname);

	f = fopen(path, "r");
	if (!f) {
		alloc_fheader();
		return;
	}

	decrypt_ids(f, &data, &dsz);
	if (!data || !dsz) {
		alloc_fheader();
		goto err;
	}

	memset(path, 0, sizeof(path));

	s = d = data; t = NULL; x = 0;
	while ((s = strtok_r(d, "\n", &t))) {
		if (d) d = NULL;

		if (iscomment(s)) continue;

		addid_init(NULL, s);
		if (idpfn) idpfn(s);
	}

err:	fclose(f);
	return;
}

void listids(void)
{
	int x;

	loadids(NULL);
	to_saveids(-1);

	if (!ids || !nids) printf("No ids found.\n");

	for (x = 0; x < nids; x++) {
		if (*(ids+x)) printf("%s\n", *(ids+x));
	}

	exit(0);
}

void saveids(void)
{
	char path[PATH_MAX];
	FILE *f = NULL;
	char *s, *d;

	if (!ids) goto out;
	if (need_to_save_ids <= 0) goto out;

	s = getenv("HOME");
	if (!s) goto out;

	memset(path, 0, sizeof(path));
	snprintf(path, PATH_MAX-1, "%s/%s", s, genpwd_ids_fname);

	f = fopen(path, "w");
	if (!f) goto out;

	memset(path, 0, sizeof(path));

	s = d = data;
	remove_deadids(data, &dsz);
	while (s && s-data < dsz) {
		d = memchr(s, '\0', dsz-(s-data));
		if (d) { *d = '\n'; s = d+1; }
		else s = NULL;
	}

	encrypt_ids(f, data, dsz);

out:	if (ids) {
		genpwd_free(ids);
		ids = NULL;
	}
	if (data) {
		memset(data, 0, dsz);
		genpwd_free(data);
	}
	if (f) fclose(f);
}

void stripchr(char *s, const char *rem)
{
	const char *rst = rem;
	char *d = s;
	int add = 0;

	while (*s) {
		while (*rem) {
			if (*s != *rem) add = 1;
			else { add = 0; break; }
			rem++;
		}

		if (add) *d++ = *s;

		s++;
		rem = rst;
	}

	memset(d, 0, s-d);
}

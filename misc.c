#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include "genpwd.h"
#include "tf1024.h"

#define _identifier "# _genpwd_ids file"

char **ids;
int nids;
static int need_to_save_ids;

static char *data = NULL;
static size_t dsz = 0;

const unsigned char *_salt = salt;
extern size_t _slen;

const unsigned char *_tweak = tweak; /* fixed size */

struct malloc_cell {
	size_t size;
	void *data;
};

static void *genpwd_zalloc(size_t sz)
{
	void *p = malloc(sz);
	if (!p) xerror("Out of memory!");
	memset(p, 0, sz);
	return p;
}

void genpwd_free(void *p)
{
	struct malloc_cell *mc;

	if (!p) return;

	mc = (struct malloc_cell *)((unsigned char *)p-sizeof(struct malloc_cell));
	if (p != mc->data) xerror("Memory allocation bug!");
	if (mc->size) {
		memset(mc->data, 0, mc->size);
		mc->size = 0;
	}
	memset(mc, 0, sizeof(struct malloc_cell));
	free(mc);
}

void *genpwd_malloc(size_t sz)
{
	struct malloc_cell *mc = genpwd_zalloc(sizeof(struct malloc_cell)+sz);

	if (mc) {
		mc->data = (void *)((unsigned char *)mc+sizeof(struct malloc_cell));
		mc->size = sz;
		return mc->data;
	}
	return NULL;
}

void *genpwd_calloc(size_t nm, size_t sz)
{
	return genpwd_malloc(nm * sz);
}

void *genpwd_realloc(void *p, size_t newsz)
{
	struct malloc_cell *mc = (struct malloc_cell *)((unsigned char *)p-sizeof(struct malloc_cell));

	if (!p) return genpwd_malloc(newsz);

	if (newsz > mc->size) {
		void *newdata = genpwd_malloc(newsz);

		if (!newdata) return NULL;
		memcpy(newdata, p, mc->size);
		genpwd_free(p);

		return newdata;
	}
	return p;
}

size_t genpwd_szalloc(const void *p)
{
	struct malloc_cell *mc = (struct malloc_cell *)((unsigned char *)p-sizeof(struct malloc_cell));
	if (!p) return 0;
	if (p != mc->data) xerror("Memory allocation bug!");
	return mc->size;
}

void xerror(const char *reason)
{
	fprintf(stderr, "%s\n", reason);
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
		strncpy(data+dsz, id, n);
		*(ids+nids) = data+dsz;
		dsz += n+1;
	}
	else *(ids+nids) = initid;

	nids++;
}

void addid(const char *id)
{
	return addid_init(id, NULL);
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

static void prepare_context(tf1024_ctx *tctx)
{
	unsigned char key[TF_KEY_SIZE];
	unsigned char ctr[TF_KEY_SIZE];

	mkpwd_adjust();

	sk1024(_salt, _slen, key, 1024);
	if (mkpwd_passes_number > 1)
		sk1024_loop(key, TF_KEY_SIZE, key, 1024, mkpwd_passes_number);
	tf1024_init(tctx);
	tf1024_set_tweak(tctx, _tweak);
	tf1024_set_key(tctx, key, TF_KEY_SIZE);
	sk1024(key, TF_KEY_SIZE, ctr, 1024);
	tf1024_start_counter(tctx, ctr);

	memset(key, 0, TF_KEY_SIZE);
	memset(ctr, 0, TF_KEY_SIZE);
}

static int decrypt_ids(FILE *f, char **data, size_t *dsz)
{
	struct stat st;
	char *ret = NULL; size_t n;
	tf1024_ctx tctx;

	if (fstat(fileno(f), &st) == -1)
		goto err;

	n = (size_t)st.st_size;
	memset(&st, 0, sizeof(struct stat));
	ret = genpwd_malloc(n+1);
	if (!ret) goto err;
	memset(ret, 0, n+1);

	prepare_context(&tctx);

	if (fread(ret, n, 1, f) < 1) goto err;
	tf1024_crypt(&tctx, ret, n, ret);
	if (strncmp(ret, _identifier, sizeof(_identifier)-1) != 0)
		goto err;

	tf1024_done(&tctx);
	*data = ret; *dsz = n;

	return 1;

err:
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

	prepare_context(&tctx);
	tf1024_crypt(&tctx, data, dsz, data);

	fwrite(data, dsz, 1, f);

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

	data = genpwd_malloc(sizeof(_identifier));
	memcpy(data, _identifier, sizeof(_identifier));
	dsz = sizeof(_identifier);
}

void loadids(ids_populate_t idpfn)
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
	snprintf(path, PATH_MAX-1, "%s/%s", s, _genpwd_ids);

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
	snprintf(path, PATH_MAX-1, "%s/%s", s, _genpwd_ids);

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

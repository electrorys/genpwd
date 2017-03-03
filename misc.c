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
#include "defs.h"

#define _identifier "# _genpwd_ids file"

char **ids;
int nids;
int need_to_save_ids;

const unsigned char *_salt = salt;
size_t _slen = sizeof(salt);

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

void dirty_ids(int dirty)
{
	need_to_save_ids = dirty;
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
	size_t l;
	int idx;

	idx = findid(id);
	if (idx == -1) return 0;

	if (*(ids+idx)) {
		l = strlen(*(ids+idx));
		memset(*(ids+idx), 0, l+1);
		free(*(ids+idx));
		*(ids+idx) = NULL;
		return 1;
	}

	return 0;
}

int dupid(const char *id)
{
	int x;

	if (iscomment(id)) return 0;

	for (x = 0; x < nids; x++) {
		if (!*(ids+x)) return 0;
		if (!strcmp(*(ids+x), id)) return 1;
	}

	return 0;
}

void addid(const char *id)
{
	if (iscomment(id)) return;

	ids = realloc(ids, sizeof(char *) * (nids + 1));
	if (!ids) return;
	*(ids+nids) = strdup(id);
	if (!*(ids+nids)) {
		ids = NULL;
		return;
	}
	nids++;
}

void freeids(void)
{
	int x;
	size_t l;

	if (!ids) return;

	for (x = 0; x < nids; x++) {
		if (!*(ids+x)) continue;
		l = strlen(*(ids+x));
		memset(*(ids+x), 0, l+1);
		free(*(ids+x));
	}

	free(ids); ids = NULL;
}

static void sk1024_loop(const unsigned char *src, size_t len, unsigned char *digest,
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

void load_defs(void)
{
	rounds = numrounds;
	offset = offs;
	passlen = plen;
}

static void prepare_context(tf1024_ctx *tctx)
{
	unsigned char key[TF_KEY_SIZE];
	unsigned char ctr[TF_KEY_SIZE];

	load_defs();

	sk1024(_salt, _slen, key, 1024);
	if (rounds > 1)
		sk1024_loop(key, TF_KEY_SIZE, key, 1024, rounds);
	tf1024_init(tctx);
	tf1024_set_tweak(tctx, tweak);
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
	ret = malloc(n+1);
	if (!ret) goto err;
	memset(ret, 0, n);

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
		free(ret);
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

void loadids(ids_populate_t idpfn)
{
	char path[PATH_MAX];
	FILE *f = NULL;
	char *data, *s, *d, *t;
	size_t dsz;

	s = getenv("HOME");
	if (!s) return;

	if (nids == -1) return;
	ids = malloc(sizeof(char *));
	if (!ids) return;

	memset(path, 0, sizeof(path));
	snprintf(path, PATH_MAX-1, "%s/%s", s, _genpwd_ids);

	f = fopen(path, "r");
	if (!f) return;

	decrypt_ids(f, &data, &dsz);
	if (!data || !dsz)
		goto err;
	*(data+dsz-1) = '\0';

	memset(path, 0, sizeof(path));

	s = d = data; t = NULL;
	while ((s = strtok_r(d, "\n", &t))) {
		if (d) d = NULL;

		if (iscomment(s)) continue;

		addid(s);
		idpfn(s);
	}

	memset(data, 0, dsz);
	free(data);
err:	fclose(f);
	return;
}

void saveids(void)
{
	char path[PATH_MAX];
	FILE *f = NULL;
	int x;
	char *s, *data, *base;
	size_t n, dsz;

	if (nids == -1) goto out;
	if (!ids) goto out;
	if (!need_to_save_ids) goto out;

	s = getenv("HOME");
	if (!s) goto out;

	memset(path, 0, sizeof(path));
	snprintf(path, PATH_MAX-1, "%s/%s", s, _genpwd_ids);

	f = fopen(path, "w");
	if (!f) goto out;

	memset(path, 0, sizeof(path));

	for (x = 0, dsz = 0; x < nids; x++) {
		if (!*(ids+x)) continue;
		dsz += strlen(*(ids+x)) + 1;
	}

	dsz += sizeof(_identifier);
	data = malloc(dsz);
	if (!data) goto out;
	memset(data, 0, dsz);
	memcpy(data, _identifier, sizeof(_identifier));

	base = data + sizeof(_identifier);
	s = base; *(s-1) = '\n'; x = 0;
	while (s-base < dsz - sizeof(_identifier)) {
		if (!*(ids+x)) goto next2;
		n = strlen(*(ids+x));
		memcpy(s, *(ids+x), n);
		*(s-1) = '\n';
		s += n+1;
next2:		x++;
	}

	*(data+dsz-1) = '\n';
	encrypt_ids(f, data, dsz);

out:	freeids();
	if (f) fclose(f);
}

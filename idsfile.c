#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <string.h>
#endif
#include "genpwd.h"

char **ids;
int nids;
static int need_to_save_ids = -2; /* init to some nonsensical value */

static char *data = NULL;
static size_t dsz = 0;

char *genpwd_ids_filename;

static int iscomment(const char *s)
{
	if (!*s
	|| *s == '#'
	|| *s == '\n'
	|| (*s == '\r' && *(s+1) == '\n')) return 1;
	return 0;
}

int will_saveids(int x)
{
	if (x == SAVE_IDS_QUERY) return need_to_save_ids;
	if (need_to_save_ids == SAVE_IDS_NEVER && x != SAVE_IDS_OVERRIDE) goto _ret;
	need_to_save_ids = x;
_ret:	return need_to_save_ids;
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
	if (!ids) will_saveids(SAVE_IDS_NEVER);

	if (!initid) {
		n = strlen(id);
		old = data;
		data = genpwd_realloc(data, dsz+n+1);
		if (!data) will_saveids(SAVE_IDS_NEVER);
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

static void prepare_context(tf1024_ctx *tctx, const void *ctr)
{
	unsigned char key[TF_KEY_SIZE], tweak[sizeof(tctx->tfc.T)-TF_SIZE_UNIT];

	sk1024(loaded_salt, salt_length, key, TF_MAX_BITS);
	if (default_passes_number > 1)
		sk1024iter(key, TF_KEY_SIZE, key, TF_MAX_BITS, default_passes_number);
	tf1024_init(tctx);
	tfc1024_set_key(&tctx->tfc, key, TF_KEY_SIZE);
	sk1024(key, sizeof(key), tweak, TF_TO_BITS(sizeof(tweak)));
	tfc1024_set_tweak(&tctx->tfc, tweak);
	tf1024_start_counter(tctx, ctr);

	memset(tweak, 0, sizeof(tweak));
	memset(key, 0, TF_KEY_SIZE);
}

static int decrypt_ids(int fd, char **data, size_t *dsz)
{
	tf1024_ctx tctx;
	char *ret = NULL;
	void *ctr;
	size_t sz;

	ctr = read_alloc_fd(fd, TF_KEY_SIZE, TF_KEY_SIZE, &sz);
	if (!ctr) goto _err;
	prepare_context(&tctx, ctr);

	ret = read_alloc_fd(fd, 256, 0, &sz);
	if (!ret) goto _err;

	/* check this before decrypt data + MAC checksum */
	if (sz <= TF_KEY_SIZE) goto _err;
	tf1024_crypt(&tctx, ret, sz-TF_KEY_SIZE, ret);

	/* check MAC checksum at end of file (tfcrypt compatible) */
	if (sz <= TF_KEY_SIZE) goto _err;
	sz -= TF_KEY_SIZE;
	tf1024_crypt(&tctx, ret+sz, TF_KEY_SIZE, ret+sz);
	sk1024(ret, sz, ctr, TF_MAX_BITS);
	if (memcmp(ret+sz, ctr, TF_KEY_SIZE) != 0) goto _err;
	genpwd_free(ctr);
	memset(ret+sz, 0, TF_KEY_SIZE);

	if (strncmp(ret, genpwd_ids_magic, CSTR_SZ(genpwd_ids_magic)) != 0)
		goto _err;

	tf1024_done(&tctx);
	*data = ret; *dsz = sz;

	return 1;

_err:
	genpwd_free(ctr);
	tf1024_done(&tctx);
	if (ret) genpwd_free(ret);
	*data = NULL;
	*dsz = 0;
	return 0;
}

static void encrypt_ids(int fd, char *data, size_t dsz)
{
	tf1024_ctx tctx;
	void *ctr;

	ctr = genpwd_malloc(TF_KEY_SIZE);
	genpwd_getrandom(ctr, TF_KEY_SIZE);
	write(fd, ctr, TF_KEY_SIZE);
	prepare_context(&tctx, ctr);

	/* data maybe even shorter - see when ids file does not exist. */
	sk1024(data, dsz, ctr, TF_MAX_BITS);
	tf1024_crypt(&tctx, data, dsz, data);
	tf1024_crypt(&tctx, ctr, TF_KEY_SIZE, ctr);

	/* write counter + data */
	write(fd, data, dsz);
	/* write MAC checksum */
	write(fd, ctr, TF_KEY_SIZE);

	genpwd_free(ctr);
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
	int fd = -1;
	char *path, *s, *d, *t;
	int x;

	if (!genpwd_ids_filename) {
		path = genpwd_malloc(PATH_MAX);
		s = getenv("HOME");
		if (!s) goto _done;
		snprintf(path, PATH_MAX, "%s/%s", s, genpwd_ids_fname);
		t = path;
	}
	else {
		path = NULL;
		t = genpwd_ids_filename;
	}

	ids = genpwd_malloc(sizeof(char *));
	if (!ids) goto _done;

	fd = open(t, O_RDONLY);
	if (fd == -1) {
		alloc_fheader();
		goto _done;
	}

	decrypt_ids(fd, &data, &dsz);
	if (!data || !dsz) {
		alloc_fheader();
		goto _err;
	}

	s = d = data; t = NULL; x = 0;
	while ((s = strtok_r(d, "\n", &t))) {
		if (d) d = NULL;

		if (iscomment(s)) continue;
		addid_init(NULL, s);
		if (idpfn) idpfn(s);
	}

_done:	genpwd_free(path);
	return;

_err:	if (fd != -1) close(fd);
	genpwd_free(path);
	return;
}

void listids(void)
{
	int x;

	loadids(NULL);
	will_saveids(SAVE_IDS_NEVER);

	if (!ids || !nids) genpwd_say("No ids found.");

	for (x = 0; x < nids; x++) {
		if (*(ids+x)) genpwd_say("%s", *(ids+x));
	}

	genpwd_exit(0);
}

void saveids(void)
{
	int fd = -1;
	char *path, *s, *d, *t;

	path = NULL;
	if (!ids) goto _out;
	if (need_to_save_ids <= SAVE_IDS_NEVER) goto _out;

	if (!genpwd_ids_filename) {
		path = genpwd_malloc(PATH_MAX);
		s = getenv("HOME");
		if (!s) goto _out;
		snprintf(path, PATH_MAX, "%s/%s", s, genpwd_ids_fname);
		t = path;
	}
	else {
		path = NULL;
		t = genpwd_ids_filename;
	}

	fd = creat(t, S_IRUSR | S_IWUSR);
	if (fd == -1) goto _out;

	s = d = data;
	remove_deadids(data, &dsz);
	while (s && s-data < dsz) {
		d = memchr(s, '\0', dsz-(s-data));
		if (d) {
			*d = '\n';
			s = d+1;
		}
		else s = NULL;
	}

	encrypt_ids(fd, data, dsz);

_out:	genpwd_free(path);
	if (ids) {
		genpwd_free(ids);
		ids = NULL;
		nids = 0;
	}
	if (data) {
		genpwd_free(data);
		data = NULL;
		dsz = 0;
	}
	if (fd != -1) close(fd);
}

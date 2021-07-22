/*
 * MIT License
 *
 * Copyright (c) 2021 Andrey Rys
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <string.h>
#endif
#include "genpwd.h"
#include "tfcore.h"

char **ids;
size_t nids;
static int need_to_save_ids = SAVE_IDS_PLEASE;

static char *data = NULL;
static size_t dsz = 0;

char *genpwd_ids_filename;

static void alloc_fheader(void)
{
	if (data && dsz) return;

	data = genpwd_malloc(sizeof(genpwd_ids_magic));
	memcpy(data, genpwd_ids_magic, sizeof(genpwd_ids_magic));
	dsz = sizeof(genpwd_ids_magic);
}

int genpwd_will_saveids(int x)
{
	if (x == SAVE_IDS_QUERY) return need_to_save_ids;
	if (need_to_save_ids == SAVE_IDS_NEVER && x != SAVE_IDS_OVERRIDE) goto _ret;
	need_to_save_ids = x;
_ret:	return need_to_save_ids;
}

static int genpwd_findid(const char *id)
{
	int x;

	for (x = 0; x < nids; x++) {
		if (ids[x]) {
			if (is_comment(ids[x])) continue;
			if (!strcmp(ids[x], id)) return x;
		}
	}

	return -1;
}

int genpwd_delid(const char *id)
{
	int idx;
	size_t n;

	if (!id) return 0;

	idx = genpwd_findid(id);
	if (idx == -1) return 0;

	if (ids[idx]) {
		n = strlen(ids[idx]);
		memset(ids[idx], 0, n);
		ids[idx] = NULL;
		return 1;
	}

	return 0;
}

int genpwd_is_dupid(const char *id)
{

	if (is_comment(id)) return 0;
	if (genpwd_findid(id) > -1) return 1;

	return 0;
}

void genpwd_addid(const char *id)
{
	size_t n;
	char *old;
	int x;

	if (genpwd_is_dupid(id)) return;

	alloc_fheader();

	ids = genpwd_realloc(ids, sizeof(char *) * (nids + 1));
	if (!ids) {
		genpwd_will_saveids(SAVE_IDS_NEVER);
		return;
	}

	n = strlen(id);
	old = data;
	data = genpwd_realloc(data, dsz+n+1);
	if (!data) {
		genpwd_will_saveids(SAVE_IDS_NEVER);
		return;
	}
	if (data != old) {
		for (x = 0; x < nids; x++) {
			if (ids[x]) ids[x] -= (old-data);
		}
	}
	memset(data+dsz, 0, n+1);
	xstrlcpy(data+dsz, id, n+1);
	ids[nids] = data+dsz;
	dsz += n+1;

	nids++;
}

static int decrypt_ids(int fd, char **data, size_t *dsz)
{
	TF_UNIT_TYPE key[TF_NR_KEY_UNITS], tag[TF_NR_BLOCK_UNITS];
	TF_BYTE_TYPE tweak[TF_TWEAK_SIZE];
	char *ret = NULL;
	void *ctr;
	size_t sz, x;

	ctr = genpwd_read_alloc_fd(fd, TF_BLOCK_SIZE, TF_BLOCK_SIZE, &sz);
	if (!ctr) goto _err;

	skein(key, TF_MAX_BITS, genpwd_salt, genpwd_szsalt);
	if (default_turns_number) {
		for (x = 0; x < default_turns_number; x++)
			skein(key, TF_MAX_BITS, key, TF_FROM_BITS(TF_MAX_BITS));
	}
	skein(tweak, TF_NR_TWEAK_BITS, key, TF_FROM_BITS(TF_MAX_BITS));
	tf_tweak_set(key, tweak);
	memset(tweak, 0, sizeof(tweak));

	ret = genpwd_read_alloc_fd(fd, GENPWD_PWD_MAX, 0, &sz);
	if (!ret) goto _err;

	/* check this before decrypt data + MAC checksum */
	if (sz <= TF_BLOCK_SIZE) goto _err;
	sz -= TF_BLOCK_SIZE;
	tf_ctr_crypt(key, ctr, ret, ret, sz);

	/* check MAC checksum at end of file (tfcrypt compatible) */
	skein(tag, TF_MAX_BITS, ret, sz);
	tf_ctr_crypt(key, ctr, ret+sz, ret+sz, TF_BLOCK_SIZE);
	if (memcmp(ret+sz, tag, TF_BLOCK_SIZE) != 0) goto _err;

	memset(key, 0, TF_BLOCK_SIZE);
	memset(tag, 0, TF_BLOCK_SIZE);
	genpwd_free(ctr);
	memset(ret+sz, 0, TF_BLOCK_SIZE);

	if (strncmp(ret, genpwd_ids_magic, CSTR_SZ(genpwd_ids_magic)) != 0)
		goto _err;

	*data = ret;
	*dsz = sz;
	return 1;

_err:
	memset(key, 0, TF_BLOCK_SIZE);
	memset(tag, 0, TF_BLOCK_SIZE);
	genpwd_free(ctr);
	if (ret) genpwd_free(ret);
	*data = NULL;
	*dsz = 0;
	return 0;
}

static void encrypt_ids(int fd, char *data, size_t dsz)
{
	TF_UNIT_TYPE key[TF_NR_KEY_UNITS], ctr[TF_NR_BLOCK_UNITS], tag[TF_NR_BLOCK_UNITS];
	TF_BYTE_TYPE tweak[TF_TWEAK_SIZE];
	size_t x;

	genpwd_getrandom(ctr, TF_BLOCK_SIZE);
	write(fd, ctr, TF_BLOCK_SIZE);

	skein(key, TF_MAX_BITS, genpwd_salt, genpwd_szsalt);
	if (default_turns_number) {
		for (x = 0; x < default_turns_number; x++)
			skein(key, TF_MAX_BITS, key, TF_FROM_BITS(TF_MAX_BITS));
	}
	skein(tweak, TF_NR_TWEAK_BITS, key, TF_FROM_BITS(TF_MAX_BITS));
	tf_tweak_set(key, tweak);
	memset(tweak, 0, sizeof(tweak));

	/* data maybe even shorter - see when ids file does not exist. */
	skein(tag, TF_MAX_BITS, data, dsz);
	tf_ctr_crypt(key, ctr, data, data, dsz);
	tf_ctr_crypt(key, ctr, tag, tag, TF_BLOCK_SIZE);

	memset(key, 0, TF_KEY_SIZE);

	/* write counter + data */
	write(fd, data, dsz);
	/* write MAC checksum */
	write(fd, tag, TF_BLOCK_SIZE);

	memset(ctr, 0, TF_BLOCK_SIZE);
	memset(tag, 0, TF_BLOCK_SIZE);
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

int genpwd_loadids_from_file(const char *path, ids_populate_fn idpfn)
{
	int fd = -1;
	char *vd = NULL;
	size_t vdsz = 0;
	char *s, *d, *t;

	if (!ids) ids = genpwd_malloc(sizeof(char *));
	if (!ids) return -1;

	fd = open(path, O_RDONLY);
	if (fd == -1) return -1;

	if (!decrypt_ids(fd, &vd, &vdsz)) {
		close(fd);
		return 0;
	}
	close(fd);

	s = d = vd; t = NULL;
	while ((s = strtok_r(d, "\n", &t))) {
		if (d) d = NULL;

		if (is_comment(s)) continue;
		genpwd_addid(s);
		if (idpfn) idpfn(s);
	}

	genpwd_free(vd);

	return 1;
}

static char *get_ids_path(void)
{
	char *path, *s;

	if (!genpwd_ids_filename) {
		path = genpwd_malloc(PATH_MAX);
		s = getenv("HOME");
		if (!s) s = "";
		snprintf(path, PATH_MAX, "%s/%s", s, genpwd_ids_fname);
	}
	else path = genpwd_strdup(genpwd_ids_filename);

	return path;
}

void genpwd_loadids(ids_populate_fn idpfn)
{
	char *path = get_ids_path();

	/* prevent overwriting of existing ids list if there is no valid key for it */
	if (genpwd_loadids_from_file(path, idpfn) == 0) genpwd_will_saveids(SAVE_IDS_NEVER);

	genpwd_free(path);
}

void genpwd_listids(gpwd_yesno shownumbers)
{
	int x;

	genpwd_loadids(NULL);
	genpwd_will_saveids(SAVE_IDS_NEVER);

	if (!ids || !nids) genpwd_say("No ids found.");

	for (x = 0; x < nids; x++) {
		if (ids[x]) {
			if (shownumbers) genpwd_say("%04x\t%s", x+1, ids[x]);
			else genpwd_say("%s", ids[x]);
		}
	}

	genpwd_exit(0);
}

void genpwd_saveids(void)
{
	int fd = -1;
	char *path, *s, *d;

	path = NULL;
	if (!ids) goto _out;
	if (need_to_save_ids <= SAVE_IDS_NEVER) goto _out;

	/* load ids again so nothing is missed. */
	genpwd_loadids(NULL);

	path = get_ids_path();

	fd = creat(path, S_IRUSR | S_IWUSR);
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

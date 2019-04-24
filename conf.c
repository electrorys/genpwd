#include "genpwd.h"

void genpwd_read_defaults(const char *path, gpwd_yesno noerr)
{
	static char ln[4096];
	char *s, *d, *t, *stoi;
	FILE *f;
	gpwd_yesno valid = NO;

	f = fopen(path, "r");
	if (!f) {
		if (noerr == YES) return;
		xerror(NO, NO, "%s", path);
	}

	while (1) {
		memset(ln, 0, sizeof(ln));
		if (genpwd_fgets(ln, sizeof(ln), f) != YES) break;

		if (valid == NO) {
			if (!strcmp(ln, "# genpwd.defs")) valid = YES;
			continue;
		}

		if (str_empty(ln) || is_comment(ln)) continue;

		s = ln;
		d = strchr(s, '=');
		if (!d) continue;
		*d = 0; d++;

		/* yay! GOTO hell! You'll "like" it! */
_spc1:		t = strchr(s, ' ');
		if (!t) goto _spc2;
		*t = 0; goto _spc1;
_spc2:		t = strchr(d, ' ');
		if (!t) goto _nspc;
		*t = 0; d = t+1; goto _spc2;
_nspc:
		if (!strcmp(s, "default_passes_number")) {
			default_passes_number = strtoul(d, &stoi, 10);
			if (!str_empty(stoi)) xerror(NO, YES, "[%s] %s: invalid passes number", path, d);
		}
		else if (!strcmp(s, "default_string_offset")) {
			default_string_offset = strtoul(d, &stoi, 10);
			if (!str_empty(stoi)) xerror(NO, YES, "[%s] %s: invalid offset number", path, d);
		}
		else if (!strcmp(s, "default_password_length")) {
			default_password_length = strtoul(d, &stoi, 10);
			if (!str_empty(stoi) || default_password_length == 0) xerror(NO, YES, "[%s] %s: invalid password length number", path, d);
		}
		else if (!strcmp(s, "genpwd_save_ids")) {
			if (!strcasecmp(d, "yes") || !strcmp(d, "1")) genpwd_save_ids = YES;
			else if (!strcasecmp(d, "no") || !strcmp(d, "0")) genpwd_save_ids = NO;
		}
		else if (!strcmp(s, "genpwd_salt")) {
			memset(genpwd_salt, 0, GENPWD_MAX_SALT);
			genpwd_szsalt = base64_decode((char *)genpwd_salt, GENPWD_MAX_SALT, d, strlen(d));
		}
		else xerror(NO, YES, "[%s] %s: unknown keyword", path, s);
	}

	memset(ln, 0, sizeof(ln));
	fclose(f);
}

void genpwd_hash_defaults(char *uhash, size_t szuhash)
{
	struct skein sk;
	gpwd_byte hash[TF_FROM_BITS(256)];
	char shash[56];

	skein_init(&sk, 256);

	skein_update(&sk, genpwd_salt, genpwd_szsalt);

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%zu", default_passes_number);
	skein_update(&sk, shash, strlen(shash));

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%zu", default_string_offset);
	skein_update(&sk, shash, strlen(shash));

	memset(shash, 0, sizeof(shash));
	sprintf(shash, "%zu", default_password_length);
	skein_update(&sk, shash, strlen(shash));

	skein_final(hash, &sk);
	memset(shash, 0, sizeof(shash));
	base64_encode(shash, (const char *)hash, sizeof(hash));
	memset(hash, 0, sizeof(hash));

	xstrlcpy(uhash, shash, szuhash);
}

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "mkpwd.h"
#include "genpwd.h"

#define _mkpwd_data_max 2

int mkpwd_passes_number = 2000, mkpwd_string_offset = 0, mkpwd_password_length = 100, mkpwd_output_format = 0;

static char *stoi;

/* Imported from rndaddr.c */
static void mkipv4(char *out, void *rnd, size_t rlen, const char *maskaddr)
{
	unsigned char *urnd = (unsigned char *)rnd;
	unsigned char addr4[4] = {0}; int prefix = 0; unsigned char c = 0;
	char tmpaddr[INET_ADDRSTRLEN] = {0};
	int i;
	char *s = NULL; const char *d = NULL;

	if (rlen < 4) goto _fail;

	s = strchr(maskaddr, '/');
	if (s && s[1]) s++;
	else goto _fail;

	prefix = strtol(s, &stoi, 10);
	if (*stoi || prefix < 0 || prefix > 32) goto _fail;

	d = maskaddr;
	strncpy(tmpaddr, d, s - d - 1);
	if (inet_pton(AF_INET, tmpaddr, addr4) != 1) goto _fail;

	if ((32 - prefix) % 8) {
		for (i = (prefix/8) + 1; i < 4; i++) addr4[i] = urnd[i];
		c = urnd[i];
		for (i = 0; i < (32 - prefix) % 8; i++) {
			if (c & (1 << i))
				addr4[prefix/8] |= (1 << i);
			else
				addr4[prefix/8] &= ~(1 << i);
		}
	}
	else
		for (i = (prefix/8); i < 4; i++) addr4[i] = urnd[i];

	if (inet_ntop(AF_INET, addr4, out, INET_ADDRSTRLEN) == NULL) goto _fail;

	return;

_fail:
	strcpy(out, "Invalid address format");
	return;
}

static void mkipv6(char *out, void *rnd, size_t rlen, const char *maskaddr)
{
	unsigned char *urnd = (unsigned char *)rnd;
	unsigned char addr6[16] = {0}; int prefix = 0; unsigned char c = 0;
	char tmpaddr[INET6_ADDRSTRLEN] = {0};
	int i;
	char *s = NULL; const char *d = NULL;

	if (rlen < 16) goto _fail;

	s = strchr(maskaddr, '/');
	if (s && s[1]) s++;
	else goto _fail;

	prefix = strtol(s, &stoi, 10);
	if (*stoi || prefix < 0 || prefix > 128) goto _fail;

	d = maskaddr;
	strncpy(tmpaddr, d, s - d - 1);
	if (inet_pton(AF_INET6, tmpaddr, addr6) != 1) goto _fail;

	if ((128 - prefix) % 8) {
		for (i = (prefix/8) + 1; i < 16; i++) addr6[i] = urnd[i];
		c = urnd[i];
		for (i = 0; i < (128 - prefix) % 8; i++) {
			if (c & (1 << i))
				addr6[prefix/8] |= (1 << i);
			else
				addr6[prefix/8] &= ~(1 << i);
		}
	}
	else
		for (i = (prefix/8); i < 16; i++) addr6[i] = urnd[i];

	if (inet_ntop(AF_INET6, addr6, out, INET6_ADDRSTRLEN) == NULL) goto _fail;

	return;

_fail:
	strcpy(out, "Invalid address format");
	return;
}

#define MAC_ADDRSTRLEN 18
static void mkmac(char *out, void *rnd, size_t rlen, const char *maskaddr)
{
	unsigned char *urnd = (unsigned char *)rnd;
	unsigned char mac[6] = {0}; int prefix = 0; unsigned char c = 0;
	char tmpaddr[MAC_ADDRSTRLEN] = {0};
	char *s = NULL; const char *d = NULL;
	int i;

	if (rlen < 6) goto _fail;

	s = strchr(maskaddr, '.');
	if (s && s[1]) s++;
	else goto _fail;

	prefix = strtol(s, &stoi, 10);
	if (*stoi || prefix < 0 || prefix > 48) goto _fail;

	d = maskaddr;
	strncpy(tmpaddr, d, s - d - 1);

	if (sscanf(maskaddr, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) < 6) goto _fail;

	if ((48 - prefix) % 8) {
		for (i = (prefix/8) + 1; i < 6; i++) mac[i] = urnd[i];
		c = urnd[i];
		for (i = 0; i < (48 - prefix) % 8; i++) {
			if (c & (1 << i))
				mac[prefix/8] |= (1 << i);
			else
				mac[prefix/8] &= ~(1 << i);
		}
	}
	else
		for (i = (prefix/8); i < 6; i++) mac[i] = urnd[i];

	if (prefix < 8) {
		if (mac[0] & (1 << 0))
			mac[0] ^= 1 << 0;
		if (mac[0] & (1 << 1))
			mac[0] ^= 1 << 1;
	}

	snprintf(out, MAC_ADDRSTRLEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return;

_fail:
	strcpy(out, "Invalid address format");
	return;
}

static void mkuuid(char *out, void *rnd, size_t rlen)
{
	unsigned char *urnd = (unsigned char *)rnd;
	if (rlen < 16) return;

	snprintf(out, 37, "%02hhx%02hhx%02hhx%02hhx"
			"-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx"
			"-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
			urnd[0], urnd[1], urnd[2], urnd[3],
			/*-*/urnd[4], urnd[5],
			/*-*/urnd[6], urnd[7],
			/*-*/urnd[8], urnd[9],
			/*-*/urnd[10], urnd[11], urnd[12], urnd[13], urnd[14], urnd[15]
	);
}

/*
 * Format of input: salt and it's length to read,
 * data: array of pointers to strings, must end with NULL pointer
 * data passed to skeincrypt: data[0] + salt + data[1] + ... + data[n]
 *
 * Returns pointer to produced password string, or error string with NUL in beginning
 */

char *mkpwd(const void *salt, size_t slen, const char **data)
{
	size_t pwdl = 0;
	sk1024_ctx ctx;
	unsigned char tmp[128];
	int i;
	static char ret[MKPWD_OUTPUT_MAX]; memset(ret, 0, sizeof(ret));

	memset(&ctx, 0, sizeof(sk1024_ctx));

	for (i = 0; data[i] && i < _mkpwd_data_max; i++)
		pwdl += strnlen(data[i], MKPWD_INPUT_MAX);
	pwdl += slen;

	if (pwdl >= MKPWD_INPUT_MAX - 1)
		return "\0Master password or name are too long";
	pwdl = 0;

	sk1024_init(&ctx, TF_MAX_BITS, 0);
	sk1024_update(&ctx, data[0], strnlen(data[0], MKPWD_INPUT_MAX));
	sk1024_update(&ctx, salt, slen);
	for (i = 1; data[i] && i < _mkpwd_data_max; i++)
		sk1024_update(&ctx, data[i], strnlen(data[i], MKPWD_INPUT_MAX));
	sk1024_final(&ctx, tmp);
	memset(&ctx, 0, sizeof(sk1024_ctx));

	if (mkpwd_passes_number)
		for (i = 0; i < mkpwd_passes_number && i < MKPWD_ROUNDS_MAX; i++)
			sk1024(tmp, sizeof(tmp), tmp, TF_MAX_BITS);

	if (mkpwd_output_format == 0) {
		unsigned char b64test[MKPWD_OUTPUT_MAX];

		b64_encode(ret, tmp, sizeof(tmp));

		if (!getenv("_GENPWD_OLDB64")) {
			memset(b64test, 0, sizeof(b64test));
			base64_encode((char *)b64test, (char *)tmp, sizeof(tmp));
			if (strncmp(ret, (char *)b64test, MKPWD_OUTPUT_MAX) != 0) {
				memset(b64test, 0, sizeof(b64test));
				memset(ret, 0, sizeof(ret));
				memset(tmp, 0, sizeof(tmp));
				return "\0New base64 failed";
			}
		}
		memset(b64test, 0, sizeof(b64test));

		stripchr(ret, "./+=");
	}
	else if (mkpwd_output_format == 4) {
		unsigned char b85test[MKPWD_OUTPUT_MAX];

		hash85(ret, tmp, sizeof(tmp));

		if (!getenv("_GENPWD_OLDB85")) {
			memset(b85test, 0, sizeof(b85test));
			base85_encode((char *)b85test, tmp, sizeof(tmp));
			if (strncmp(ret, (char *)b85test, MKPWD_OUTPUT_MAX) != 0) {
				memset(b85test, 0, sizeof(b85test));
				memset(ret, 0, sizeof(ret));
				memset(tmp, 0, sizeof(tmp));
				return "\0New base85 failed";
			}
		}
		memset(b85test, 0, sizeof(b85test));
	}
	else if (mkpwd_output_format == 5) {
		unsigned char b95test[MKPWD_OUTPUT_MAX];

		hash95(ret, tmp, sizeof(tmp));

		if (!getenv("_GENPWD_OLDB95")) {
			memset(b95test, 0, sizeof(b95test));
			base95_encode((char *)b95test, tmp, sizeof(tmp));
			if (strncmp(ret, (char *)b95test, MKPWD_OUTPUT_MAX) != 0) {
				memset(b95test, 0, sizeof(b95test));
				memset(ret, 0, sizeof(ret));
				memset(tmp, 0, sizeof(tmp));
				return "\0New base95 failed";
			}
		}
		memset(b95test, 0, sizeof(b95test));
	}
	else if (mkpwd_output_format == 0x1004) {
		mkipv4(ret, tmp, sizeof(tmp), data[2]);
		goto _fastret;
	}
	else if (mkpwd_output_format == 0x1006) {
		mkipv6(ret, tmp, sizeof(tmp), data[2]);
		goto _fastret;
	}
	else if (mkpwd_output_format == 0x1001) {
		mkmac(ret, tmp, sizeof(tmp), data[2]);
		goto _fastret;
	}
	else if (mkpwd_output_format == 0xff) {
		mkuuid(ret, tmp, sizeof(tmp));
		goto _fastret;
	}
	else {
		int i, d;
		char tmpc[4] = {0};

		for (i = 0, d = 0; i < sizeof(tmp) && d < MKPWD_OUTPUT_MAX; i++)
			switch (mkpwd_output_format) {
			case 1:
			default:
				d+=snprintf(tmpc, 4, "%hhu", tmp[i]);
				if ((unsigned char)tmp[i] > 100) {
					if (tmpc[0] == '1') tmpc[2]++;
					if (tmpc[0] == '2') tmpc[2] += 2;
					if (tmpc[2] > '9') tmpc[2] -= 10;
					d--;
				}
				if (d > MKPWD_OUTPUT_MAX) continue;
				strncat(ret,
					(unsigned char)tmp[i] > 100 ? tmpc+1 : tmpc,
					sizeof(ret) - strlen(ret));
				break;
			case 2:
				d+=snprintf(ret+d, 3, "%hhx", tmp[i]);
				break;
			case 3:
				d+=snprintf(ret+d, 4, "%hho", tmp[i]);
				break;
			}
		memset(tmpc, 0, sizeof(tmpc));
	}

	memmove(ret, ret+mkpwd_string_offset, mkpwd_password_length);
	memset(ret+mkpwd_password_length, 0, sizeof(ret)-mkpwd_password_length);

_fastret:
	memset(tmp, 0, sizeof(tmp));
	return ret;
}

/*
 * Format of input: salt and it's length to read,
 * data: array of pointers to strings, must end with NULL pointer
 * data passed to skeincrypt: data[0] + salt + data[1] + ... + data[n]
 *
 * Returns pointer to produced key buffer, or error string with NUL in beginning
 */

void *mkpwbuf(const void *salt, size_t slen, const char **data)
{
	size_t pwdl = 0;
	sk1024_ctx ctx;
	int i;
	static char *ret;

	memset(&ctx, 0, sizeof(sk1024_ctx));

	if (!mkpwd_password_length || mkpwd_password_length >= 0x10000)
		return "\0Requested output size is bigger than 64K";

	for (i = 0; data[i] && i < _mkpwd_data_max; i++)
		pwdl += strnlen(data[i], MKPWD_INPUT_MAX);
	pwdl += slen;

	if (pwdl >= MKPWD_INPUT_MAX - 1)
		return "\0Master password or name are too long";
	pwdl = 0;

	ret = genpwd_malloc(mkpwd_password_length);
	if (!ret) return "\0Can't allocate memory";

	sk1024_init(&ctx, TF_TO_BITS(mkpwd_password_length), 0);
	sk1024_update(&ctx, data[0], strnlen(data[0], MKPWD_INPUT_MAX));
	sk1024_update(&ctx, salt, slen);
	for (i = 1; data[i] && i < _mkpwd_data_max; i++)
		sk1024_update(&ctx, data[i], strnlen(data[i], MKPWD_INPUT_MAX));
	sk1024_final(&ctx, ret);
	memset(&ctx, 0, sizeof(sk1024_ctx));

	if (mkpwd_passes_number)
		for (i = 0; i < mkpwd_passes_number && i < MKPWD_ROUNDS_MAX; i++)
			sk1024(ret, mkpwd_password_length, ret, TF_TO_BITS(mkpwd_password_length));

	return ret;
}

#undef _mkpwd_data_max

char *mkpwd_hint(const void *salt, size_t slen, const char *pw)
{
	static char mhash[TF_BLOCK_SIZE];
	sk1024_ctx ctx;
	char *ret;

	memset(&ctx, 0, sizeof(sk1024_ctx));
	memset(mhash, 0, sizeof(mhash));

	sk1024_init(&ctx, 16, 0);
	sk1024_update(&ctx, pw, strnlen(pw, MKPWD_INPUT_MAX));
	sk1024_update(&ctx, salt, slen);
	sk1024_final(&ctx, mhash);

	ret = mhash + (sizeof(mhash)/2);
	snprintf(ret, (sizeof(mhash)/2), "%02hx%02hx", (uint8_t)mhash[0], (uint8_t)mhash[1]);

	memset(&ctx, 0, sizeof(sk1024_ctx));
	memset(mhash, 0, (sizeof(mhash)/2));

	return ret;
}

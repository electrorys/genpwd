/*
 * base85.c : encode numbers using two different techniques for Base-85 
 * PUBLIC DOMAIN - Jon Mayo - September 10, 2008
 *
 * Modified and imported by Lynx for genpwd program.
 * -- 23Mar2017.
 */
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <endian.h>
#include "mkpwd.h"

#define NR(x) (sizeof(x)/sizeof(*x))

#define BASE85_DIGITS 5	 /* log85 (2^32) is 4.9926740807112 */
#define BASE95_DIGITS 5	 /* log95 (2^32) is 4.8707310948237 */
static unsigned char base85[85];
static signed char dbase85[UCHAR_MAX];
static unsigned char base95[95];
static signed char dbase95[UCHAR_MAX];

static inline void data_to_be32(void *p, size_t l)
{
	size_t idx;
	uint32_t *P = (uint32_t *)p;
	uint32_t t;

	for (idx = 0; idx < (l/sizeof(uint32_t)); idx++) {
		t = htobe32(P[idx]);
		P[idx] = t;
	}
}


/* create a look up table suitable for convering characters to base85 digits */
static void base85_init(void)
{
	static int init_done;
	unsigned char ch;

	if (init_done) return;

	for (ch = 0; ch < 85; ch++)
		base85[ch] = ' ' + ch;

	for (ch = 0; ch < UCHAR_MAX; ch++)
		dbase85[ch] = -1;

	for (ch = 0; ch < 85; ch++)
		dbase85[base85[ch]] = ch;

	init_done = 1;
}

/* create a look up table suitable for convering characters to base85 digits */
static void base95_init(void)
{
	static int init_done;
	unsigned char ch;

	if (init_done) return;

	for (ch = 0; ch < 95; ch++)
		base95[ch] = ' ' + ch;

	for (ch = 0; ch < UCHAR_MAX; ch++)
		dbase95[ch] = -1;

	for (ch = 0; ch < 95; ch++)
		dbase95[base95[ch]] = ch;

	init_done = 1;
}

/*
 * convert a list of 32-bit values into a base85 string.
 * example:
 *   input: "Lion"
 *   ascii85: 9PJE_
 */
static int __base85_encode(char *out, size_t max, const uint32_t *data, size_t count)
{
	size_t i;
	uint32_t n;

	base85_init();

	while (count) {
		if (max < 1) return 0; /* failure */
		n = *data++;
		data_to_be32(&n, sizeof(uint32_t));
		if (count >= sizeof(uint32_t))
			count -= sizeof(uint32_t);
		else count = 0;

		if (n == 0) {
			*out++ = '\0'; /* must be 'z', but there is NUL. */
			max--;
		}
		else {
			if (max < BASE85_DIGITS) return 0; /* no room */
			for (i = BASE85_DIGITS; i--; ) {
				out[i] = base85[n % 85];
				n /= 85;
			}
			max -= BASE85_DIGITS;
			out += BASE85_DIGITS;
		}
	}
	*out = 0;

	return 1; /* success */
}

static int __base95_encode(char *out, size_t max, const uint32_t *data, size_t count)
{
	size_t i;
	uint32_t n;

	base95_init();

	while (count) {
		if (max < 1) return 0; /* failure */
		n = *data++;
		data_to_be32(&n, sizeof(uint32_t));
		if (count >= sizeof(uint32_t))
			count -= sizeof(uint32_t);
		else count = 0;

		if (n == 0) {
			*out++ = '\0';
			max--;
		}
		else {
			if (max < BASE95_DIGITS) return 0; /* no room */
			for (i = BASE95_DIGITS; i--; ) {
				out[i] = base95[n % 95];
				n /= 95;
			}
			max -= BASE95_DIGITS;
			out += BASE95_DIGITS;
		}
	}
	*out = 0;

	return 1; /* success */
}

void base85_encode(char *dst, const unsigned char *src, size_t count)
{
	(void)__base85_encode(dst, count * 2 > MKPWD_OUTPUT_MAX ? MKPWD_OUTPUT_MAX : count * 2, (const uint32_t *)src, count);
}

void base95_encode(char *dst, const unsigned char *src, size_t count)
{
	(void)__base95_encode(dst, count * 2 > MKPWD_OUTPUT_MAX ? MKPWD_OUTPUT_MAX : count * 2, (const uint32_t *)src, count);
}

/*
 * convert a base85 string into a list of 32-bit values
 * treats string as if it were padded with 0s
 */
#if 0
int base85_decode(uint32_t *out, size_t out_count, const char *in)
{
	unsigned in_count;
	uint32_t n, k;

	base85_init();

	if (*in == 0) return 0; /* nothing to decode */
	while (*in) {
		if (out_count <= 0) return 0; /* failure - not enough space in destination */
		n = 0;
		/* 'z' is a special way to encode 4 bytes of 0s */
		if (*in == 'z') {
			in++;
		}
		else {
			for (in_count=0, k=1; *in && in_count < BASE85_DIGITS; in_count++) {
				signed d; /* digit */

				d = dbase85[(unsigned char)*in++];
				if (d < 0) return 0; /* failure - invalid character */
				n = n * 85 + d;
			}
		}
		*out++ = n;
		out_count--;
	}
	return 1; /* success */
}

int base85_test(int verbose)
{
	static const uint32_t testdata[] = {
		0x4c696f6e, 0x0ddba11, 0xba5eba11, 0xbeef, 0xcafe,
		0xb00b, 0xdeadbea7, 0xdefec8, 0xbedabb1e, 0xf01dab1e, 0xf005ba11, 0xb01dface,
		0x5ca1ab1e, 0xcab005e, 0xdeadfa11, 0x1eadf007, 0xdefea7,
		~0UL, 0, 1, (unsigned)-8, (unsigned)-9, 0x4d616e20, 0x206e614d,
	};

	char buf[5 * NR(testdata) + 1];
	uint32_t testout[NR(testdata)];
	size_t i;

	base85_init();

	if (!base85_encode(buf, sizeof(buf), testdata, NR(testdata))) return 0;

	if (!base85_decode(testout, NR(testout), buf)) return 0;

	for (i = 0; i < NR(testdata); i++) {
		if (testdata[i] != testout[i])
			return 0; /* failure */
	}

	if (!base85_decode(&testout[0], 1, "Ll100")) return 0;
	if (!base85_decode(&testout[1], 1, "Ll1")) return 0;
	if (!base85_decode(&testout[2], 1, "00Ll1")) return 0;

	return 1; /* pass */
}
#endif

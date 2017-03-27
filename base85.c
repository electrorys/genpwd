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
	(void)__base85_encode(dst, ((count / 4) + count) + 1, (const uint32_t *)src, count);
}

void base95_encode(char *dst, const unsigned char *src, size_t count)
{
	(void)__base95_encode(dst, ((count / 4) + count) + 1, (const uint32_t *)src, count);
}

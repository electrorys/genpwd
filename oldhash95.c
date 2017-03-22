/*
 * This code is based on git's base85.c, but there also other versions of this floating around
 * Converted to full-ascii version, possibly with loss of data inside (one-way for passwords)
 * While recover of data is possible from b85 version, it is possible that b95 loses some bits,
 * but it is enough for generating a string from binary stream, even if it (maybe) lossy...
 */


#include <stdint.h>
#include <string.h>

static uint8_t entab[95];

static void mktab85(void)
{
	int i;

	memset(entab, 0, sizeof(entab));
	for (i = 0; i < 85; i++) entab[i] = ' ' + i;
}

void hash85(char *dst, const unsigned char *src, size_t len)
{
	size_t x = len;
	uint32_t cc = 0, ch = 0, cv = 0;
	int cnt;

	if (!entab[0]) mktab85();
	while (x) {
		for (cnt = 24; cnt >= 0; cnt -= 8) {
			ch = *src++;
			cc |= ch << cnt;
			if (x-- == 0) break;
		}
		for (cnt = 4; cnt >= 0; cnt--) {
			cv = cc % 85;
			cc /= 85;
			dst[cnt] = entab[cv];
		}
		dst += 5;
	}
	*dst = 0;
}

static void mktab95(void)
{
	int i;

	memset(entab, 0, sizeof(entab));
	for (i = 0; i < 95; i++) entab[i] = ' ' + i;
}

void hash95(char *dst, const unsigned char *src, size_t len)
{
	size_t x = len;
	uint32_t cc = 0, ch = 0, cv = 0;
	int cnt;

	if (!entab[0]) mktab95();
	while (x) {
		for (cnt = 24; cnt >= 0; cnt -= 8) {
			ch = *src++;
			cc |= ch << cnt;
			if (x-- == 0) break;
		}
		for (cnt = 4; cnt >= 0; cnt--) {
			cv = cc % 95;
			cc /= 95;
			dst[cnt] = entab[cv];
		}
		dst += 5;
	}
	*dst = 0;
}

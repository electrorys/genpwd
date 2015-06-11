#include <string.h>
#include <stdlib.h>

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(char *dst, const unsigned char *src, size_t length)
{
	unsigned char in[3] = {0};
	char *p = NULL;
	int i, len = 0;
	int j = 0;

	dst[0] = '\0'; p = dst;
	while (j < length) {
		len = 0;
		for (i=0; i<3; i++) {
			in[i] = (unsigned char) src[j];
			if (j < length) {
				len++; j++;
			}
			else in[i] = 0;
		}
		if (len) {
			p[0] = b64[in[0] >> 2];
			p[1] = b64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
			p[2] = (unsigned char) (len > 1 ? b64[((in[1] & 0x0f) << 2) |
				((in[2] & 0xc0) >> 6)] : '=');
			p[3] = (unsigned char) (len > 2 ? b64[in[2] & 0x3f] : '=');
			p[4] = '\0';
			p += 4;
		}
	}
}

#if 0
static void b64_decode(unsigned char *dst, const char *src, size_t len)
{
	int c, phase, i;
	unsigned char in[4] = {0};
	char *p = NULL, *d = NULL;

	phase = 0; i=0; d = dst;
	while (src[i] && i < len)
	{
		c = (int) src[i];
		if (c == '=') {
			d[0] = in[0] << 2 | in[1] >> 4;
			d[1] = in[1] << 4 | in[2] >> 2;
			d[2] = in[2] << 6 | in[3] >> 0;
			d += 3;
			break;
		}
		p = strchr(b64, c);
		if (p) {
			in[phase] = p - b64;
			phase = (phase + 1) % 4;
			if (phase == 0) {
				d[0] = in[0] << 2 | in[1] >> 4;
				d[1] = in[1] << 4 | in[2] >> 2;
				d[2] = in[2] << 6 | in[3] >> 0;
				d += 3;
				in[0] = in[1] = in[2] = in[3] = 0;
			}
		}
		i++;
	}
}
#endif

static void stripchr(char *s, const char *rem)
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

#include <string.h>
#include <stdlib.h>

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void b64_encode(char *dst, const unsigned char *src, size_t length)
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

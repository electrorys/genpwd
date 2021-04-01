/* Source: https://gist.github.com/jarcode-foss/c39bacf97cd88a02d7c6d6d70b482dd5 */

#include "genpwd.h"
#include <forms.h>

/* BMP Image header */
struct __attribute__((packed)) bmp_header {
	uint16_t header;
	uint32_t size;
	uint16_t reserved0, reserved1;
	uint32_t offset;
	/* BITMAPINFOHEADER */
	uint32_t header_size, width, height;
	uint16_t planes, bits_per_pixel;
	uint32_t compression, image_size, hres, vres, colors, colors_used;
};

struct bmp_pixel {
	uint8_t B, G, R, A;
};

#define BMP_HEADER_MAGIC 0x4D42
#define BMP_BITFIELDS 3

static inline const struct bmp_pixel *bmp_get_pixel(const struct bmp_pixel *bp, size_t h, size_t x, size_t y)
{
	return &bp[x+(y*h)];
}

int xwin_assign_icon_bmp(Display *d, Window w, const void *image)
{
	const struct bmp_header *hdr = (const struct bmp_header *)image;
	const struct bmp_pixel *bp, *pix;
	unsigned long *conv_data;
	size_t sz, x, y;
	Atom NWI;

	if (!hdr) return 0;
	if (hdr->header != BMP_HEADER_MAGIC) return 0;
	if (hdr->bits_per_pixel != 32) return 0;
	if (hdr->planes != 1 || hdr->compression != BMP_BITFIELDS) return 0;

	NWI = XInternAtom(d, "_NET_WM_ICON", False);

	bp = (const struct bmp_pixel *)(((const uint8_t *)hdr)+hdr->offset);

	sz = 2+hdr->width*hdr->height;
	conv_data = genpwd_malloc(sz*sizeof(unsigned long));
	conv_data[0] = hdr->width;
	conv_data[1] = hdr->height;

	for (x = 0; x < hdr->width; x++) {
		for (y = 0; y < hdr->height; y++) {
			pix = bmp_get_pixel(bp, hdr->height, x, y);
			conv_data[x+(((hdr->height-1)-y)*hdr->height)+2] = (~pix->A << 24) | (pix->R << 16) | (pix->G << 8) | pix->B;
		}
	}

	XChangeProperty(d, w, NWI, XA_CARDINAL, 32, PropModeReplace, (const unsigned char *)conv_data, sz);
	genpwd_free(conv_data);

	return 1;
}
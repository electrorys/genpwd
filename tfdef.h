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

#ifndef _THREEFISH_CIPHER_DEFINITIONS_HEADER
#define _THREEFISH_CIPHER_DEFINITIONS_HEADER

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

/* config block */
/* #define TF_256BITS */
/* #define TF_512BITS */
#define TF_1024BITS
/* #define TF_NO_ENDIAN */
/* #define TF_BIG_ENDIAN */

#include <stddef.h>
#include <stdint.h>
#ifndef TF_NO_ENDIAN
#include <sys/param.h>
#else
#undef TF_BIG_ENDIAN
#endif

#define TF_UNIT_TYPE uint64_t

#ifdef TF_BIG_ENDIAN
#define TF_SWAP_FUNC htobe64
#else
#define TF_SWAP_FUNC htole64
#endif

#if defined(TF_256BITS)
#define TF_NR_BLOCK_BITS 256
#define TF_NR_KEY_BITS 512
#define TF_NR_BLOCK_UNITS 4
#define TF_NR_KEY_UNITS 8
#define IRR_POLY_CONST 0x425
#elif defined(TF_512BITS)
#define TF_NR_BLOCK_BITS 512
#define TF_NR_KEY_BITS 768
#define TF_NR_BLOCK_UNITS 8
#define TF_NR_KEY_UNITS 12
#define IRR_POLY_CONST 0x125
#elif defined(TF_1024BITS)
#define TF_NR_BLOCK_BITS 1024
#define TF_NR_KEY_BITS 1280
#define TF_NR_BLOCK_UNITS 16
#define TF_NR_KEY_UNITS 20
#define IRR_POLY_CONST 0x80043
#else
#error Please edit tfdef.h include file and select at least one cipher!
#endif

#define TF_BYTE_TYPE uint8_t
#define TF_SIZE_UNIT (sizeof(TF_UNIT_TYPE))
#define TF_BLOCK_SIZE (TF_SIZE_UNIT * TF_NR_BLOCK_UNITS)
#define TF_KEY_SIZE (TF_SIZE_UNIT * TF_NR_KEY_UNITS)

#define TF_NR_TWEAK_UNITS 2
#define TF_NR_TWEAK_BITS 128
#define TF_TWEAK_SIZE (TF_SIZE_UNIT * TF_NR_TWEAK_UNITS)
#define TF_TWEAKEY_SIZE (TF_KEY_SIZE - (2 * TF_TWEAK_SIZE))
#define TF_NR_TWEAKEY_BITS (TF_NR_KEY_BITS - (2 * TF_NR_TWEAK_BITS))
#define TF_TWEAK_WORD1 (TF_NR_KEY_UNITS-3)
#define TF_TWEAK_WORD2 (TF_NR_KEY_UNITS-2)
#define TF_TWEAK_WORD3 (TF_NR_KEY_UNITS-1)

#define TF_TO_BITS(x) ((x) * 8)
#define TF_FROM_BITS(x) ((x) / 8)
#define TF_MAX_BITS TF_NR_BLOCK_BITS
#define TF_UNIT_BITS (TF_SIZE_UNIT * 8)

#define TF_TO_BLOCKS(x) ((x) / TF_BLOCK_SIZE)
#define TF_FROM_BLOCKS(x) ((x) * TF_BLOCK_SIZE)
#define TF_BLOCKS_TO_BYTES(x) TF_FROM_BLOCKS(x)
#define TF_BLOCKS_FROM_BYTES(x) TF_TO_BLOCKS(x)

static inline void data_to_words(void *p, size_t l)
{
#ifndef TF_NO_ENDIAN
	size_t idx;
	TF_UNIT_TYPE *P = p;
	TF_UNIT_TYPE t;

	for (idx = 0; idx < (l/sizeof(TF_UNIT_TYPE)); idx++) {
		t = TF_SWAP_FUNC(P[idx]);
		P[idx] = t;
	}
#endif
}

static inline void ctr_inc(TF_UNIT_TYPE *x, size_t xl)
{
	size_t z;

	for (z = 0; z < xl; z++) {
		x[z] = ((x[z] + (TF_UNIT_TYPE)1) & ((TF_UNIT_TYPE)~0));
		if (x[z]) break;
	}
}

static inline void ctr_add(TF_UNIT_TYPE *x, size_t xl, const TF_UNIT_TYPE *y, size_t yl)
{
	size_t z, cf;
	TF_UNIT_TYPE t;

	for (z = 0, cf = 0; z < xl; z++) {
		t = x[z] + (z >= yl ? (TF_UNIT_TYPE)0 : y[z]) + cf;
		if (cf) cf = (x[z] >= t ? 1 : 0);
		else cf = (x[z] > t ? 1 : 0);
		x[z] = t;
	}
}

#define tf_convkey(k) do { data_to_words(k, TF_KEY_SIZE); } while (0)

void tf_encrypt_rawblk(TF_UNIT_TYPE *O, const TF_UNIT_TYPE *I, const TF_UNIT_TYPE *K);
void tf_decrypt_rawblk(TF_UNIT_TYPE *O, const TF_UNIT_TYPE *I, const TF_UNIT_TYPE *K);

void tf_ctr_crypt(const void *key, void *ctr, void *out, const void *in, size_t sz);

void tf_tweak_set(void *key, const void *tweak);

#endif

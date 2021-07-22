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

/*
 * This file is a part of SMalloc.
 * SMalloc is MIT licensed.
 * Copyright (c) 2017 Andrey Rys.
 */

#include "smalloc_i.h"

/* An adopted Jenkins one-at-a-time hash */
#define UIHOP(x, s) do {		\
		hash += (x >> s) & 0xff;\
		hash += hash << 10;	\
		hash ^= hash >> 6;	\
	} while (0)
uintptr_t smalloc_uinthash(uintptr_t x)
{
	uintptr_t hash = 0;

	UIHOP(x, 0);
	UIHOP(x, 8);
	UIHOP(x, 16);
	UIHOP(x, 24);

	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;

	return hash;
}
#undef UIHOP

uintptr_t smalloc_mktag(struct smalloc_hdr *shdr)
{
	uintptr_t r = smalloc_uinthash(PTR_UINT(shdr));
	r += shdr->rsz;
	r = smalloc_uinthash(r);
	r += shdr->usz;
	r = smalloc_uinthash(r);
	return r;
}

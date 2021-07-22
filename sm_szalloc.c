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

size_t sm_szalloc_pool(struct smalloc_pool *spool, const void *p)
{
	struct smalloc_hdr *shdr;

	if (!smalloc_verify_pool(spool)) {
		errno = EINVAL;
		return ((size_t)-1);
	}

	if (!p) return 0;

	shdr = USER_TO_HEADER(p);
	if (smalloc_is_alloc(spool, shdr)) return shdr->usz;
	smalloc_UB(spool, p);
	return 0;
}

size_t sm_szalloc(const void *p)
{
	return sm_szalloc_pool(&smalloc_curr_pool, p);
}

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

#include <string.h>
#include "tfdef.h"

void tf_ctr_crypt(const void *key, void *ctr, void *out, const void *in, size_t sz)
{
	const TF_BYTE_TYPE *uin = in;
	TF_BYTE_TYPE *uout = out;
	TF_UNIT_TYPE x[TF_NR_BLOCK_UNITS], y[TF_NR_BLOCK_UNITS];
	TF_UNIT_TYPE *uctr = ctr;
	const TF_UNIT_TYPE *ukey = key;
	size_t sl = sz, i;

	if (sl >= TF_BLOCK_SIZE) {
		do {
			memcpy(x, uin, TF_BLOCK_SIZE);
			uin += TF_BLOCK_SIZE;
			data_to_words(x, TF_BLOCK_SIZE);

			ctr_inc(uctr, TF_NR_BLOCK_UNITS);
			tf_encrypt_rawblk(y, uctr, ukey);
			for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] ^= x[i];

			data_to_words(y, TF_BLOCK_SIZE);
			memcpy(uout, y, TF_BLOCK_SIZE);
			uout += TF_BLOCK_SIZE;
		} while ((sl -= TF_BLOCK_SIZE) >= TF_BLOCK_SIZE);
	}

	if (sl) {
		memset(x, 0, TF_BLOCK_SIZE);
		memcpy(x, uin, sl);
		data_to_words(x, TF_BLOCK_SIZE);

		ctr_inc(uctr, TF_NR_BLOCK_UNITS);
		tf_encrypt_rawblk(y, uctr, ukey);
		for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] ^= x[i];

		data_to_words(y, TF_BLOCK_SIZE);
		memcpy(uout, y, sl);
	}

	memset(x, 0, TF_BLOCK_SIZE);
	memset(y, 0, TF_BLOCK_SIZE);
}

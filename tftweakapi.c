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
#include "tfcore.h"

void tf_tweak_set(void *key, const void *tweak)
{
	TF_UNIT_TYPE *ukey = key;
	TF_UNIT_TYPE *twe = ukey+TF_TWEAK_WORD1;
	TF_UNIT_TYPE c = THREEFISH_CONST;
	size_t x;

	for (x = 0; x < TF_NR_BLOCK_UNITS; x++) c ^= ukey[x];
	ukey[x] = c;

	if (!tweak) {
		memset(twe, 0, (TF_NR_TWEAK_UNITS+1)*TF_SIZE_UNIT);
		return;
	}

	memcpy(twe, tweak, TF_NR_TWEAK_UNITS*TF_SIZE_UNIT);
	data_to_words(twe, TF_NR_TWEAK_UNITS*TF_SIZE_UNIT);
	ukey[TF_TWEAK_WORD3] = ukey[TF_TWEAK_WORD1] ^ ukey[TF_TWEAK_WORD2];
}

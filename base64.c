/*
 * base64.c: libb64 compressed code. Public domain.
 * See http://libb64.sourceforge.net/ for original code and infos.
 *
 * See also liblynx library for full version of this code.
 *
 * Modified and fixed by Lynx <lynx@lynxlynx.ru> 03Jun2016:
 * - Single TU, minimal external dependencies
 * - Stream operation, no newline insertions
 * - Fixed code style to pure K&R
 * - Fixed integer overflows and fixed size types
 * - Fixed out of bounds access in base64_decode_block 
 * - Force specify output size for output buffer when decoding
 * - Fixed signed/unsigned issue on ARM
 * - Added generic memory converter wrappers which do not expose internals
 * - All functions calculate number of processed characters and return them to caller
 */

#include <stdlib.h>
#include <string.h>
#include "genpwd.h"

enum base64_encodestep {
	dstep_a, dstep_b, dstep_c
};

struct base64_encodestate {
	enum base64_encodestep step;
	char result;
	size_t count;
};

void base64_init_encodestate(struct base64_encodestate *state_in)
{
	state_in->step = dstep_a;
	state_in->result = 0;
	state_in->count = 0;
}

char base64_encode_value(char value_in)
{
	static const char *encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (value_in > 63) return '=';
	return encoding[(int)value_in];
}

size_t base64_encode_block(const char *plaintext_in, size_t length_in, char *code_out, struct base64_encodestate *state_in)
{
	const char *plainchar = plaintext_in;
	const char *const plaintextend = plaintext_in + length_in;
	char *codechar = code_out;
	char result;
	char fragment;
	
	result = state_in->result;
	
	switch (state_in->step) {
		while (1) {
			case dstep_a:
					if (plainchar == plaintextend) {
						state_in->result = result;
						state_in->step = dstep_a;
						state_in->count += (codechar - code_out);
						return codechar - code_out;
					}
					fragment = *plainchar++;
					result = (fragment & 0xfc) >> 2;
					*codechar++ = base64_encode_value(result);
					result = (fragment & 0x03) << 4;
			case dstep_b:
					if (plainchar == plaintextend) {
						state_in->result = result;
						state_in->step = dstep_b;
						state_in->count += (codechar - code_out);
						return codechar - code_out;
					}
					fragment = *plainchar++;
					result |= (fragment & 0xf0) >> 4;
					*codechar++ = base64_encode_value(result);
					result = (fragment & 0x0f) << 2;
			case dstep_c:
					if (plainchar == plaintextend) {
						state_in->result = result;
						state_in->step = dstep_c;
						state_in->count += (codechar - code_out);
						return codechar - code_out;
					}
					fragment = *plainchar++;
					result |= (fragment & 0xc0) >> 6;
					*codechar++ = base64_encode_value(result);
					result  = (fragment & 0x3f) >> 0;
					*codechar++ = base64_encode_value(result);
		}
	}
	/* control should not reach here */
	state_in->count += (codechar - code_out);
	return codechar - code_out;
}

size_t base64_encode_blockend(char *code_out, struct base64_encodestate *state_in)
{
	char *codechar = code_out + state_in->count;
	
	switch (state_in->step) {
		case dstep_b:
			*codechar++ = base64_encode_value(state_in->result);
			*codechar++ = '=';
			*codechar++ = '=';
			state_in->count += 3;
			break;
		case dstep_c:
			*codechar++ = base64_encode_value(state_in->result);
			*codechar++ = '=';
			state_in->count += 2;
			break;
		case dstep_a:
			break;
	}

	return codechar - code_out;
}

size_t base64_encode(char *output, const char *input, size_t inputl)
{
	struct base64_encodestate estate;
	size_t r;

	base64_init_encodestate(&estate);
	base64_encode_block(input, inputl, output, &estate);
	base64_encode_blockend(output, &estate);

	r = estate.count;
	memset(&estate, 0, sizeof(struct base64_encodestate));

	return r;
}

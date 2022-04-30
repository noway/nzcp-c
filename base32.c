/**
 * base32 (de)coder implementation as specified by RFC4648.
 *
 * Copyright (c) 2010 Adrien Kunysz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 **/

#include <assert.h>  // assert()
#include <limits.h>  // CHAR_BIT

#include "base32.h"

static const unsigned char PADDING_CHAR = '=';
static const unsigned char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Decode given character into a 5 bits value. 
 * Returns -1 iff the argument given was an invalid base32 character
 * or a padding character.
 */
static int decode_char(unsigned char c)
{
	signed char retval = -1;

	if (c >= 'A' && c <= 'Z')
		retval = c - 'A';
	if (c >= '2' && c <= '7')
		retval = c - '2' + 26;

	assert(retval == -1 || ((retval & 0x1F) == retval));

	return  retval;
}

/**
 * Given a block id between 0 and 7 inclusive, this will return the index of
 * the octet in which this block starts. For example, given 3 it will return 1
 * because block 3 starts in octet 1:
 *
 * +--------+--------+
 * | ......<|.3 >....|
 * +--------+--------+
 *  octet 1 | octet 2
 */
static int get_octet(int block)
{
	assert(block >= 0 && block < 8);
	return (block*5) / 8;
}

/**
 * Given a block id between 0 and 7 inclusive, this will return how many bits
 * we can drop at the end of the octet in which this block starts. 
 * For example, given block 0 it will return 3 because there are 3 bits
 * we don't care about at the end:
 *
 *  +--------+-
 *  |< 0 >...|
 *  +--------+-
 *
 * Given block 1, it will return -2 because there
 * are actually two bits missing to have a complete block:
 *
 *  +--------+-
 *  |.....< 1|..
 *  +--------+-
 **/
static int get_offset(int block)
{
	assert(block >= 0 && block < 8);
	return (8 - 5 - (5*block) % 8);
}

/**
 * Like "b >> offset" but it will do the right thing with negative offset.
 * We need this as bitwise shifting by a negative offset is undefined
 * behavior.
 */
static unsigned char shift_right(unsigned char byte, signed char offset)
{
	if (offset > 0)
		return byte >>  offset;
	else
		return byte << -offset;
}

static unsigned char shift_left(unsigned char byte, signed char offset)
{
	return shift_right(byte, - offset);
}

static int decode_sequence(const unsigned char *coded, unsigned char *plain)
{
	assert(CHAR_BIT == 8);
	assert(coded && plain);

	plain[0] = 0;
	for (int block = 0; block < 8; block++) {
		int offset = get_offset(block);
		int octet = get_octet(block);

		int c = decode_char(coded[block]);
		if (c < 0)  // invalid char, stop here
			return octet;

		plain[octet] |= shift_left(c, offset);
		if (offset < 0) {  // does this block overflows to next octet?
			assert(octet < 4);
			plain[octet+1] = shift_left(c, 8 + offset);
		}
	}
	return 5;
}

static inline size_t base32_decode(const unsigned char *coded, unsigned char *plain) 
{
	size_t written = 0;
	for (size_t i = 0, j = 0; ; i += 8, j += 5) {
		int n = decode_sequence(&coded[i], &plain[j]);
		written += n;
		if (n < 5)
			return written;
	}
}
/**
 * copyright 2002, 2003 Bryce "Zooko" Wilcox-O'Hearn
 * mailto:zooko@zooko.com
 *
 * See the end of this file for the free software, open source license (BSD-style).
 */
#ifndef __INCL_base32_h
#define __INCL_base32_h

static char const* const base32_h_cvsid = "$Id: base32.h,v 1.11 2003/12/15 01:16:19 zooko Exp $";

static int const base32_vermaj = 0;
static int const base32_vermin = 9;
static int const base32_vermicro = 12;
static char const* const base32_vernum = "0.9.12";

#include <assert.h>
#include <stddef.h>

/* Types from zstr */
/**
 * A zstr is simply an unsigned int length and a pointer to a buffer of
 * unsigned chars.
 */
typedef struct {
	size_t len; /* the length of the string (not counting the null-terminating character) */
	unsigned char* buf; /* pointer to the first byte */
} zstr;

/**
 * A zstr is simply an unsigned int length and a pointer to a buffer of
 * const unsigned chars.
 */
typedef struct {
	size_t len; /* the length of the string (not counting the null-terminating character) */
	const unsigned char* buf; /* pointer to the first byte */
} czstr;

/**
 * @param os the data to be encoded in a zstr
 *
 * @return the contents of `os' in base-32 encoded form in a (newly allocated) zstr
 */
zstr b2a(const czstr os);

/**
 * @param os the data to be encoded in a zstr
 * @param lengthinbits the number of bits of data in `os' to be encoded
 *
 * b2a_l() will generate a base-32 encoded string big enough to encode lengthinbits bits.  So for 
 * example if os is 2 bytes long and lengthinbits is 15, then b2a_l() will generate a 3-character-
 * long base-32 encoded string (since 3 quintets is sufficient to encode 15 bits).  If os is 2 bytes
 * long and lengthinbits is 16 (or None), then b2a_l() will generate a 4-character string.  Note 
 * that `b2a_l()' does not mask off unused least-significant bits, so for example if os is 2 bytes 
 * long and lengthinbits is 15, then you must ensure that the unused least-significant bit of os is 
 * a zero bit or you will get the wrong result.  This precondition is tested by assertions if 
 * assertions are enabled.
 *
 * Warning: if you generate a base-32 encoded string with `b2a_l()', and then someone else tries to 
 * decode it by calling `a2b()' instead of  `a2b_l()', then they will (probably) get a different 
 * string than the one you encoded!  So only use `b2a_l()' when you are sure that the encoding and 
 * decoding sides know exactly which `lengthinbits' to use.  If you do not have a way for the 
 * encoder and the decoder to agree upon the lengthinbits, then it is best to use `b2a()' and 
 * `a2b()'.  The only drawback to using `b2a()' over `b2a_l()' is that when you have a number of 
 * bits to encode that is not a multiple of 8, `b2a()' can sometimes generate a base-32 encoded 
 * string that is one or two characters longer than necessary.
 *
 * @return the contents of `os' in base-32 encoded form in a (newly allocated) zstr
 *
 * On memory exhaustion, return a "null" zstr with .buf == NULL and .len
 * == 0.
 */
zstr b2a_l(const czstr cs, const size_t lengthinbits);
zstr b2a_l_extra_Duffy(const czstr cs, const size_t lengthinbits);

/**
 * @param data to be zbase-32 encoded
 * @param length size of the data buffer
 *
 * @return an allocated string containing the zbase-32 encoded representation
 */
char *zbase32_encode(const unsigned char *data, size_t length);

/*xxxx

c_b2a = None
c_a2b = None
c_could_be_base32_encoded_octets = None
c_could_be_base32_encoded = None*/

#endif /* #ifndef __INCL_base32_h */

/**
 * Copyright (c) 2002 Bryce "Zooko" Wilcox-O'Hearn
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software to deal in this software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of this software, and to permit
 * persons to whom this software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of this software.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THIS SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 * THIS SOFTWARE.
 */

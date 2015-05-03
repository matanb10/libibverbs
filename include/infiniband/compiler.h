/*
 * Copyright (c) 2015 Mellanox, Ltd.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _COMPILER_
#define _COMPILER_

#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#define ibv_popcount64		__builtin_popcountll
#endif

#ifndef __has_builtin
	#define __has_builtin(x) 0 /* Compatibility with non-clang compilers. */
#endif

#if __has_builtin(__builtin_popcountll) && !defined(ibv_popcount64)
	#define ibv_popcount64		__builtin_popcountll
#endif

#ifndef ibv_popcount64
/* Code taken from LLVM. All rights reserved to LLVM project */
static inline int ibv_popcount64(uint64_t x)
{
	/*binary: 0101...*/
	static const unsigned long long m1  = 0x5555555555555555;
	/*binary: 00110011..*/
	static const unsigned long long m2  = 0x3333333333333333;
	/*binary:  4 zeros,  4 ones ...*/
	static const unsigned long long m4  = 0x0f0f0f0f0f0f0f0f;
	/*the sum of 256 to the power of 0,1,2,3...*/
	static const unsigned long long h01 = 0x0101010101010101;

	/*put count of each 2 bits into those 2 bits*/
	x -= (x >> 1) & m1;
	/*put count of each 4 bits into those 4 bits*/
	x = (x & m2) + ((x >> 2) & m2);
	/*put count of each 8 bits into those 8 bits*/
	x = (x + (x >> 4)) & m4;
	/*returns left 8 bits of x + (x<<8) + (x<<16) + (x<<24) + ...*/
	return (x * h01) >> 56;
}
#endif

#endif

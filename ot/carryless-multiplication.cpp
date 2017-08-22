/*
 * carryless-multiplication.cpp
 *
 *  Created on: 18.08.2017
 *      Author: Matthias
 */

#include "carryless-multiplication.h"


//#define USE_INTEL_INSTRUCTIONS

#ifdef USE_INTEL_INSTRUCTIONS

#include <wmmintrin.h>

// !!! only works for nBytes == 128 !!!
// as of now this is merely an example to see how efficient a native implementation of carryless multiplication can be.
// dont' forget to build with support for native instructions!
//
// code is taken from libOTe with minor modifications.
void carrylessMultiplication(uint8_t *a, uint8_t *b, uint8_t *r, uint32_t nBytes) {
	__m128i _a = *(__m128i *)a;
	__m128i _b = *(__m128i *)b;

	__m128i t1 = _mm_clmulepi64_si128(_a, _b, (int)0x00);
	__m128i t2 = _mm_clmulepi64_si128(_a, _b, 0x10);
	__m128i t3 = _mm_clmulepi64_si128(_a, _b, 0x01);
	__m128i t4 = _mm_clmulepi64_si128(_a, _b, 0x11);

    t2 = _mm_xor_si128(t2, t3);
    t3 = _mm_slli_si128(t2, 8);
    t2 = _mm_srli_si128(t2, 8);
    t1 = _mm_xor_si128(t1, t3);
    t4 = _mm_xor_si128(t4, t2);

    ((__m128i *)r)[0] ^= t1;
    ((__m128i *)r)[1] ^= t4;

}

#else

// fallback, if nBytes is not a multiple of 4
// this is much, much slower though!
// as an alternative you could consider the lookup table based version at the bottom of this file
void safeCarrylessMultiplication(uint8_t *a, uint8_t *b, uint8_t *r, uint32_t nBytes) {
	for (uint32_t aIndex = 0; aIndex < nBytes; aIndex++) {
		for (uint32_t bIndex = 0; bIndex < nBytes; bIndex++) {
			uint32_t rIndex = aIndex + bIndex;
			uint32_t x = a[aIndex];
			uint32_t y = b[bIndex];

			uint32_t z =
					((x & 0x00000001) ? y : 0) ^
					((x & 0x00000002) ? (y << 1) : 0) ^
					((x & 0x00000004) ? (y << 2) : 0) ^
					((x & 0x00000008) ? (y << 3) : 0) ^
					((x & 0x00000010) ? (y << 4) : 0) ^
					((x & 0x00000020) ? (y << 5) : 0) ^
					((x & 0x00000040) ? (y << 6) : 0) ^
					((x & 0x00000080) ? (y << 7) : 0);

			r[rIndex] ^= z;
			r[rIndex + 1] ^= z >> 8;
		}
	}

}

void carrylessMultiplication(uint8_t *a, uint8_t *b, uint8_t *r, uint32_t nBytes) {
	if (nBytes % 4) {
		safeCarrylessMultiplication(a, b, r, nBytes);
		return;
	}

	for (uint32_t aIndex = 0; aIndex < nBytes; aIndex += 4) {
		for (uint32_t bIndex = 0; bIndex < nBytes; bIndex += 4) {
			uint32_t rIndex = aIndex + bIndex;
			uint32_t x = a[aIndex] | (a[aIndex + 1] << 8) | (a[aIndex + 2] << 16) | (uint32_t)(a[aIndex + 3] << 24);
			uint64_t y = b[bIndex] | (b[bIndex + 1] << 8) | (b[bIndex + 2] << 16) | (uint32_t)(b[bIndex + 3] << 24);

			uint64_t z =
					((x & 0x00000001) ? y : 0) ^
					((x & 0x00000002) ? (y << 1) : 0) ^
					((x & 0x00000004) ? (y << 2) : 0) ^
					((x & 0x00000008) ? (y << 3) : 0) ^
					((x & 0x00000010) ? (y << 4) : 0) ^
					((x & 0x00000020) ? (y << 5) : 0) ^
					((x & 0x00000040) ? (y << 6) : 0) ^
					((x & 0x00000080) ? (y << 7) : 0) ^
					((x & 0x00000100) ? (y << 8) : 0) ^
					((x & 0x00000200) ? (y << 9) : 0) ^
					((x & 0x00000400) ? (y << 10) : 0) ^
					((x & 0x00000800) ? (y << 11) : 0) ^
					((x & 0x00001000) ? (y << 12) : 0) ^
					((x & 0x00002000) ? (y << 13) : 0) ^
					((x & 0x00004000) ? (y << 14) : 0) ^
					((x & 0x00008000) ? (y << 15) : 0) ^
					((x & 0x00010000) ? (y << 16) : 0) ^
					((x & 0x00020000) ? (y << 17) : 0) ^
					((x & 0x00040000) ? (y << 18) : 0) ^
					((x & 0x00080000) ? (y << 19) : 0) ^
					((x & 0x00100000) ? (y << 20) : 0) ^
					((x & 0x00200000) ? (y << 21) : 0) ^
					((x & 0x00400000) ? (y << 22) : 0) ^
					((x & 0x00800000) ? (y << 23) : 0) ^
					((x & 0x01000000) ? (y << 24) : 0) ^
					((x & 0x02000000) ? (y << 25) : 0) ^
					((x & 0x04000000) ? (y << 26) : 0) ^
					((x & 0x08000000) ? (y << 27) : 0) ^
					((x & 0x10000000) ? (y << 28) : 0) ^
					((x & 0x20000000) ? (y << 29) : 0) ^
					((x & 0x40000000) ? (y << 30) : 0) ^
					((x & 0x80000000) ? (y << 31) : 0);

			r[rIndex] ^= z;
			r[rIndex + 1] ^= z >> 8;
			r[rIndex + 2] ^= z >> 16;
			r[rIndex + 3] ^= z >> 24;
			r[rIndex + 4] ^= z >> 32;
			r[rIndex + 5] ^= z >> 40;
			r[rIndex + 6] ^= z >> 48;
			r[rIndex + 7] ^= z >> 56;
		}
	}

}



/*
 * OLD LOOKUP TABLE BASED IMPLEMENTATION
 * for nBytes % 4 != 0 this might actually be faster than safeCarrylessMultiplication (if the entire lookup table can be cached)


#include "../ENCRYPTO_utils/thread.h"

// this lock is used to make sure the lookup table is only built once
CLock lutLock;

// holds the results for carryless multiplication of individual bytes. Each such multiplication produces a two-byte result
// which means this table will be 2 * 256 * 256 Bytes = 128 KB big. Hopefully it can be completely cached or else performance will drop!
uint8_t *lookup = 0;

// even if this function is called by multiple threads, the lookup table is only built once.
void buildCarrylessMultiplicationLUT() {
	lutLock.Lock();
	if (lookup) {
		lutLock.Unlock();
		return;
	}


	lookup = new uint8_t[2 * 256 * 256];
	uint16_t *lookup16 = (uint16_t *)lookup;

	for (uint32_t a = 0; a < 256; a++) {
		for (uint32_t b = 0; b < 256; b++) {
			lookup16[(a << 8) | b] =
					((a & 1) ? b : 0) ^
					((a & 2) ? (b << 1) : 0) ^
					((a & 4) ? (b << 2) : 0) ^
					((a & 8) ? (b << 3) : 0) ^
					((a & 16) ? (b << 4) : 0) ^
					((a & 32) ? (b << 5) : 0) ^
					((a & 64) ? (b << 6) : 0) ^
					((a & 128) ? (b << 7) : 0);
		}
	}
	lutLock.Unlock();
}

void carrylessMultiplication(uint8_t *a, uint8_t *b, uint8_t *r, uint32_t nBytes) {
	if (!lookup)
		buildCarrylessMultiplicationLUT();

	for (uint32_t aIndex = 0; aIndex < nBytes; aIndex++) {
		for (uint32_t bIndex = 0; bIndex < nBytes; bIndex++) {
			uint32_t lookupIndex = ((a[aIndex] << 8) | b[bIndex]) << 1;
			uint32_t rIndex = aIndex + bIndex;
			// more efficient to lookup and xor individual bytes instead of uint16_t values!
			// probably for alignment reasons.
			r[rIndex] ^= lookup[lookupIndex];
			r[rIndex + 1] ^= lookup[lookupIndex + 1];
		}
	}

}

*/

#endif

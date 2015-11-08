// mersenne.h - written and placed in public domain by Jeffrey Walton. Copyright assigned to Crypto++ project.

#ifndef CRYPTOPP_MERSENNE_TWISTER_H
#define CRYPTOPP_MERSENNE_TWISTER_H

#include "../cryptlib.h"
#include "../secblock.h"
#include "../misc.h"

#include <iostream>
using namespace std;

NAMESPACE_BEGIN(CryptoPP)

//! Mersenne Twister class for Monte-Carlo simulations
/*!
 * \param K magic constant
 * \param M period parameter
 * \param N size of the state vector
 * \param F multiplier constant
 * \param S default seed
 */
template <unsigned int K, unsigned int M, unsigned int N, unsigned int F, unsigned long S>
class MersenneTwister : public RandomNumberGenerator
{
public:
	//! construct a Mersenne Twister
	//! \param seed seed for the generator, defaults to template parameter S due to changing algorithm parameters over time
	MersenneTwister(unsigned long seed = S) : m_seed(seed), m_idx(N)
	{
		m_state[0] = seed;
		for (unsigned int i = 1; i < N+1; i++)
			m_state[i] = word32(F * (m_state[i-1] ^ (m_state[i-1] >> 30)) + i);
	}

	virtual ~MersenneTwister()
	{
		*((volatile word32*)&m_seed) = *((volatile word32*)&m_idx) = 0;
	}

	//! generate random array of bytes
	//! Bytes are written to @output in big endian order. If @output length is not a multiple of word32, then
	//! unused bytes are not accumulated for subsequent calls to @GenerateBlock. Rather, the unused tail bytes
	//! are discarded, and the stream is continued at the next word32 boundary from the state array.
	//! \param output byte buffer
	//! \param size length of the buffer, in bytes
	virtual void GenerateBlock(byte *output, size_t size)
	{
		// Handle word32 size blocks
		word32 temp;
		for (size_t i=0; i < size/4; i++, output += 4)
		{
#if defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && defined(IS_LITTLE_ENDIAN)
			*((word32*)output) = ByteReverse(NextMersenneWord());
#elif defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS)
			*((word32*)output) = NextMersenneWord();
#else
			temp = NextMersenneWord();
			output[3] = CRYPTOPP_GET_BYTE_AS_BYTE(temp, 0);
			output[2] = CRYPTOPP_GET_BYTE_AS_BYTE(temp, 1);
			output[1] = CRYPTOPP_GET_BYTE_AS_BYTE(temp, 2);
			output[0] = CRYPTOPP_GET_BYTE_AS_BYTE(temp, 3);
#endif
		}

		// Calculate tail bytes
		const size_t tail = size%4;

		// No tail bytes
		if (tail == 0)
		{
			// Wipe temp
			*((volatile word32*)&temp) = 0;
			return;
		}

		// Handle tail bytes
		temp = NextMersenneWord();
		switch (tail)
		{
			case 3: output[2] = CRYPTOPP_GET_BYTE_AS_BYTE(temp, 1); /* fall through */
			case 2: output[1] = CRYPTOPP_GET_BYTE_AS_BYTE(temp, 2); /* fall through */
			case 1: output[0] = CRYPTOPP_GET_BYTE_AS_BYTE(temp, 3); break;

			default: assert(0); ;;
		}

		// Wipe temp
		*((volatile word32*)&temp) = 0;
	}

	//! generate a random 32 bit word in the range min to max, inclusive
	//! If the 32 bit candidate is not within the range, then it is discarded and a new candidate is used.
	virtual word32 GenerateWord32(word32 min=0, word32 max=0xffffffffL)
	{
		assert(max > min);
		const word32 range = max-min;
		if (range == 0xffffffffL)
			return NextMersenneWord();
			
		const int maxBits = BitPrecision(range);
		word32 value;

		do {
			value = Crop(NextMersenneWord(), maxBits);
		} while (value > range);

		return value+min;
	}

	//! generate and discard n bytes
	//! If @n is not a multiple of word32, then unused bytes are not accumulated for subsequent calls to
	//! @GenerateBlock. Rather, the unused tail bytes are discarded, and the stream is continued at the
	//! next word32 boundary from the state array.
	//! \param n the number of bytes to discard, rounded up to a word32 size
	virtual void DiscardBytes(size_t n)
	{
		for(size_t i=0; i < (n+3)/4; i++)
			NextMersenneWord();
	}
	
protected:

	word32 NextMersenneWord()
	{
		if (m_idx >= N) { Twist(); }
		
		word32 temp = m_state[m_idx++];
		temp ^= (temp >> 11);
		temp ^= (temp <<  7) & 0x9D2C5680; // 2636928640
		temp ^= (temp << 15) & 0xEFC60000; // 4022730752
		
		return temp ^ (temp >> 18);
	}

	void Twist()
	{			
		static const unsigned long magic[2]={0x0UL, K};
		word32 kk, temp;

		assert(N >= M);
		for (kk=0;kk<N-M;kk++)
		{
			temp = (m_state[kk] & 0x80000000)|(m_state[kk+1] & 0x7FFFFFFF);
			m_state[kk] = m_state[kk+M] ^ (temp >> 1) ^ magic[temp & 0x1UL];
		}
		
		for (;kk<N-1;kk++)
		{
			temp = (m_state[kk] & 0x80000000)|(m_state[kk+1] & 0x7FFFFFFF);
			m_state[kk] = m_state[kk+(M-N)] ^ (temp >> 1) ^ magic[temp & 0x1UL];
		}
		
		temp = (m_state[N-1] & 0x80000000)|(m_state[0] & 0x7FFFFFFF);
		m_state[N-1] = m_state[M-1] ^ (temp >> 1) ^ magic[temp & 0x1UL];
		
		// Reset index
		m_idx = 0;
	
		// Wipe temp
		*((volatile word32*)&temp) = 0;
	}

private:

	FixedSizeSecBlock<word32, N+1> m_state;
	unsigned int m_seed, m_idx;
};

// http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/ARTICLES/mt.pdf;
//! uses 69069 as multiplier and 4537 as default seed.
typedef MersenneTwister<0x9908B0DF /*2567483615*/, 397, 624, 0x10DCD /*69069*/, 4537> MT19937;

// http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/emt19937ar.html;
//! uses 1812433253 and multiplier and 5489 as default seed.
typedef MersenneTwister<0x9908B0DF /*2567483615*/, 397, 624, 0x6C078965 /*1812433253*/, 5489> MT19937ar;

NAMESPACE_END

#endif // CRYPTOPP_MERSENNE_TWISTER_H
	

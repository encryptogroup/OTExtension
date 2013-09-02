/*
 * XORMasking.h
 *
 *  Created on: May 13, 2013
 *      Author: mzohner
 */

#ifndef XORMASKING_H_
#define XORMASKING_H_

#include "maskingfunction.h"

class XORMasking : public MaskingFunction
{
public:
	BYTE* buf;
	XORMasking(int bitlength){m_nBitLength = bitlength; buf = (BYTE*) malloc(sizeof(BYTE) * CEIL_DIVIDE(bitlength, 8)); };
	~XORMasking(){if(m_nBitLength > 0) free(buf);};

	void Mask(int progress, int processedOTs, CBitVector* values, CBitVector& snd_buf, CBitVector& delta)
	{
		int bitPos = progress * m_nBitLength;
		int bytePos = CEIL_DIVIDE(bitPos, 8);

		//cout << "Performing masking for " << bitPos << " to " << bitPos + (len*8) << endl;
		values[1].SetBits(values[0].GetArr() + bytePos, bitPos, processedOTs * m_nBitLength);
		values[1].XORBits(delta.GetArr() + bytePos, bitPos, processedOTs * m_nBitLength);

		snd_buf.XORBits(values[1].GetArr() + bytePos, 0, processedOTs * m_nBitLength);
	};

	void UnMask(int progress, int processedOTs, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf)
	{
		int lim = processedOTs * m_nBitLength;
		for(int l= 0; l < lim; progress++, l+=m_nBitLength)
		{
			if(choices.GetBitNoMask(progress))
			{
				output.XORBitsPosOffset(rcv_buf.GetArr(), l, progress*m_nBitLength, m_nBitLength);
			}
		}
	};

private:
	int m_nBitLength;
};

#endif /* XORMASKING_H_ */

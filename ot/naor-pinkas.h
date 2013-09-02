/*
 * Compute the Naor-Pinkas Base OTs
 */

#ifndef __Naor_Pinkas_H_
#define __Naor_Pinkas_H_

#include "baseOT.h"

class NaorPinkas : public BaseOT
{

	public:

	NaorPinkas(){};
	~NaorPinkas(){};
	
	NaorPinkas(int secparam, BYTE* seed, bool useecc){Init(secparam, seed, useecc);};

	// Sender and receiver method using GMP
#ifdef OTEXT_USE_GMP
	BOOL ReceiverIFC(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL SenderIFC(int nSndVals, int nOTs, CSocket& sock,  BYTE* ret);
#endif
	
	// Sender and receiver method using Miracl
	BOOL ReceiverECC(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL SenderECC(int nSndVals, int nOTs, CSocket& sock, BYTE* ret);

	
};
		


#endif

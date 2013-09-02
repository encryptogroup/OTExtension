/*
 * asharov-lindell.h
 *
 *  Created on: Mar 20, 2013
 *      Author: mzohner
 */

#ifndef ASHAROVLINDELL_H_
#define ASHAROVLINDELL_H_

#include "baseOT.h"

class AsharovLindell : public BaseOT
{
	public:
	AsharovLindell(){};
	~AsharovLindell(){};

	AsharovLindell(int secparam, BYTE* seed, bool useecc){Init(secparam, seed, useecc);};

#ifdef OTEXT_USE_GMP
	// Sender and receiver method using GMP
	BOOL ReceiverIFC(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL SenderIFC(int nSndVals, int nOTs, CSocket& sock, BYTE* ret);
#endif
	
	// Sender and receiver method using Miracl
	BOOL ReceiverECC(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL SenderECC(int nSndVals, int nOTs, CSocket& sock, BYTE* ret);


};

#endif /* ASHAROVLINDELL_H_ */

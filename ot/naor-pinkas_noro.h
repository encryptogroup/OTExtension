/*
 * The Naor-Pinkas OT protocols that does not require a random oracle
 */

#ifndef __Naor_Pinkas_NORO_H_
#define __Naor_Pinkas_NORO_H_

#include "baseOT.h"

class NaorPinkasNoRO : public BaseOT
{

	public:

	~NaorPinkasNoRO(){};
	
	NaorPinkasNoRO(crypto* crypt, field_type ftype) :
		BaseOT(crypt, ftype) {
}
	void Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, BYTE* ret);
	void Sender(uint32_t nSndVals, uint32_t nOTs, channel* chan, BYTE* ret);


	
};
		


#endif

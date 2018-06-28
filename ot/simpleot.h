/*
 * Compute the Simple OT protocol from Tung Chou and Claudio Orlandi on http://eprint.iacr.org/2015/267
 */

#ifndef __SIMPLEOT_H_
#define __SIMPLEOT_H_

#include "baseOT.h"

class channel;
class CBitVector;

class SimpleOT : public BaseOT
{

	public:
	
	SimpleOT(crypto* crypt, field_type ftype):
		BaseOT(crypt, ftype) {
	}
	;

	void Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, BYTE* ret);
	void Sender(uint32_t nSndVals, uint32_t nOTs, channel* chan, BYTE* ret);

	
};

#endif

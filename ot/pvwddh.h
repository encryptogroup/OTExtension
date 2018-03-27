/*
 * Compute the Base OTs using the Peikert-Vakuntanathan-Waters OT based on DDH in decryption mode (PVW08)
 */

#ifndef __PVWDDH_H_
#define __PVWDDH_H_

#include "baseOT.h"

class PVWDDH : public BaseOT
{

	public:

	~PVWDDH(){};
	
	PVWDDH(crypto* crypt, field_type ftype):
		BaseOT(crypt, ftype) {
	}
	;

	void Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, BYTE* ret);
	void Sender(uint32_t nSndVals, uint32_t nOTs, channel* chan, BYTE* ret);

	
};

#endif

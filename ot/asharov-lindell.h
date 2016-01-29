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
	~AsharovLindell(){};

	AsharovLindell(crypto* crypt, field_type ftype) :
		BaseOT(crypt, ftype) {
}
;
	void Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, BYTE* ret);
	void Sender(uint32_t nSndVals, uint32_t nOTs, channel* chan, BYTE* ret);


};

#endif /* ASHAROVLINDELL_H_ */

/*
 * iknp-ot-ext-receiver.h
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */


/*
 * ot-extension-receiver.h
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */

#ifndef IKNP_OT_EXTENSION_RECEIVER_H_
#define IKNP_OT_EXTENSION_RECEIVER_H_

#include "ot-ext-rec.h"


class IKNPOTExtRec : public OTExtRec {
	/*
	 * OT receiver part
	 * Input:
	 * nSndVals: perform a 1-out-of-nSndVals OT
	 * nOTs: the number of OTs that shall be performed
	 * choices: a vector containing nBaseOTs choices in the domain 0-(SndVals-1)
	 * ret: returns the resulting bit representations, Has to initialized to a byte size of: nOTs * state.field_size
	 *
	 * Output: was the execution successful?
	 */
public:
	IKNPOTExtRec(uint32_t nSndVals, crypto* crypt, CSocket* sock, BYTE* keybytes) {
		InitRec(nSndVals, crypt, sock, keybytes, crypt->get_seclvl().symbits);
	}
	;


	~IKNPOTExtRec() {
		//TODO
		//free(m_vKeySeedMtx);
	}
	;

	BOOL receiver_routine(uint32_t threadid, uint64_t numOTs);
};

#endif /* OT_EXTENSION_RECEIVER_H_ */

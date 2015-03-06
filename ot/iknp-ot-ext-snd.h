/*
 * iknp-ot-ext-sender.h
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */

#ifndef IKNP_OT_EXT_SENDER_H_
#define IKNP_OT_EXT_SENDER_H_

#include "ot-ext-snd.h"

class IKNPOTExtSnd : public OTExtSnd {

public:
	IKNPOTExtSnd(uint32_t nSndVals, crypto* crypt, CSocket* sock, CBitVector& U, BYTE* keybytes) {
		InitSnd(nSndVals, crypt, sock, U, keybytes, crypt->get_seclvl().symbits);
	}
	;


	~IKNPOTExtSnd() {
		//TODO
		//free(m_vKeySeedMtx);
	}
	;

	BOOL sender_routine(uint32_t threadid, uint64_t numOTs);
};



#endif /* IKNP_OT_EXT_SENDER_H_ */

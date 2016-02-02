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
	IKNPOTExtSnd(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread) {
		InitSnd(crypt, rcvthread, sndthread, crypt->get_seclvl().symbits);
	}
	;


	~IKNPOTExtSnd() {	};

	BOOL sender_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);
};



#endif /* IKNP_OT_EXT_SENDER_H_ */

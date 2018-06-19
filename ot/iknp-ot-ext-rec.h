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

public:
	IKNPOTExtRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint64_t num_ot_blocks=4096, bool verify_ot=true, bool use_fixed_key_aes_hashing=false)
		: OTExtRec(num_ot_blocks, verify_ot, use_fixed_key_aes_hashing) {
		InitRec(crypt, rcvthread, sndthread, crypt->get_seclvl().symbits);
	}
	;


	virtual ~IKNPOTExtRec() {}	;

	BOOL receiver_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);
};

#endif /* OT_EXTENSION_RECEIVER_H_ */

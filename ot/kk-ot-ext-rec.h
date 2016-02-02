/*
 * kk-ot-ext-receiver.h
 *
 *  Created on: Aug 20, 2015
 *      Author: mzohner
 */


#ifndef KK_OT_EXTENSION_RECEIVER_H_
#define KK_OT_EXTENSION_RECEIVER_H_

#include "ot-ext-rec.h"
#include "../util/codewords.h"
#include "kk-ot-ext.h"

class KKOTExtRec : public OTExtRec, public KKOTExt {
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
	KKOTExtRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread) {
		uint32_t numbaseots = 2*crypt->get_seclvl().symbits;//, pad_to_power_of_two(nSndVals));

		//assert(pad_to_power_of_two(nSndVals) == nSndVals); //TODO right now only supports power of two nSndVals
		assert(numbaseots == 256); //TODO: right now only 256 base OTs work due to the size of the code
		InitRec(crypt, rcvthread, sndthread, 2*crypt->get_seclvl().symbits);


		//Initialize the code words
		InitAndReadCodeWord(&m_vCodeWords);
	}
	;


	~KKOTExtRec() {
		//TODO
		//free(m_vKeySeedMtx);
	}
	;

	BOOL receiver_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);

private:
	void GenerateChoiceCodes(CBitVector& choicecodes, CBitVector& vSnd, CBitVector& T, uint32_t startpos, uint32_t len);
	void KKSetOutput(CBitVector* maskbuf, uint64_t otid, uint64_t otlen, queue<mask_block*>* mask_queue, channel* chan);
	void KKHashValues(CBitVector& T, CBitVector& seedbuf, CBitVector* maskbuf, uint64_t OT_ptr, uint64_t OT_len, uint64_t** mat_mul);
	void KKMaskBaseOTs(CBitVector& T, CBitVector& SndBuf, uint64_t numblocks);
	void KKReceiveAndUnMask(channel* chan, queue<mask_block*>* mask_queue);
	//uint64_t** m_vCodeWords;
};

#endif /* KK_OT_EXTENSION_RECEIVER_H_ */

#ifndef OOS_OT_EXTENSION_RECEIVER_H_
#define OOS_OT_EXTENSION_RECEIVER_H_

#include "ot-ext-rec.h"
#include "kk-ot-ext.h"

class OOSOTExtRec : public OTExtRec, public KKOTExt {

public:
	// s is a statistical security parameter determining the number of additional OTs
	OOSOTExtRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t s = 40) {
		m_nAdditionalOTs = s;
		uint32_t numbaseots = 2*crypt->get_seclvl().symbits;//, pad_to_power_of_two(nSndVals));

		//assert(pad_to_power_of_two(nSndVals) == nSndVals); //TODO right now only supports power of two nSndVals
		assert(numbaseots == 256); //TODO: right now only 256 base OTs work due to the size of the code
		InitRec(crypt, rcvthread, sndthread, 2*crypt->get_seclvl().symbits);


		//Initialize the code words
		InitAndReadCodeWord(&m_vCodeWords);
	}
	;


	virtual ~OOSOTExtRec() {
		//TODO
		//free(m_vKeySeedMtx);
	}
	;

	BOOL receiver_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);

private:
	void GenerateChoiceCodes(CBitVector* choicecodes, CBitVector* vSnd, CBitVector* T, uint32_t startpos, uint32_t len);

	// even though this is OOS, not KK, I did not rename these functions to make it clear that they were not modified
	void KKSetOutput(CBitVector* maskbuf, uint64_t otid, uint64_t otlen, queue<mask_block*>* mask_queue, channel* chan);
	void KKHashValues(CBitVector* T, CBitVector* seedbuf, CBitVector* maskbuf, uint64_t OT_ptr, uint64_t OT_len, uint64_t** mat_mul);
	void KKMaskBaseOTs(CBitVector* T, CBitVector* SndBuf, uint64_t numblocks);
	void KKReceiveAndUnMask(channel* chan, queue<mask_block*>* mask_queue);
	//uint64_t** m_vCodeWords;

	// performs all the OOS specific tasks:
	// - exchange additional OTs
	// - receive random weights from server (as a seed)
	// - calculate + send checksums
	void OOSCheck(vector<CBitVector *> &T_list, channel *chan, uint64_t internal_numOTs, uint64_t firstOTid);

	uint32_t m_nAdditionalOTs;
};

#endif /* OOS_OT_EXTENSION_RECEIVER_H_ */

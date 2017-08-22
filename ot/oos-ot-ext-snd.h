#ifndef OOS_OT_EXT_SENDER_H_
#define OOS_OT_EXT_SENDER_H_

#include "ot-ext-snd.h"
#include "kk-ot-ext.h"

class OOSOTExtSnd : public OTExtSnd, public KKOTExt {

public:
	// s is a statistical security parameter determining the number of additional OTs
	OOSOTExtSnd(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t s = 40) {
		m_nAdditionalOTs = s;
		uint32_t numbaseots = 2*crypt->get_seclvl().symbits;

		//assert(pad_to_power_of_two(nSndVals) == nSndVals); //TODO right now only supports power of two nSndVals
		assert(numbaseots == 256); //TODO: right now only 256 base OTs work due to the size of the code
		InitSnd(crypt, rcvthread, sndthread, 2*crypt->get_seclvl().symbits);
		//Initialize the code words
		InitAndReadCodeWord(&m_vCodeWords);
	}
	;


	virtual ~OOSOTExtSnd() {
	}
	;

	BOOL sender_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);

private:
	// even though this is OOS, not KK, I did not rename these functions to make it clear that they were not modified
	void KKHashValues(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint64_t OT_ptr, uint64_t OT_len, uint64_t** mat_mul);
	void KKMaskAndSend(CBitVector* snd_buf, uint64_t OT_ptr, uint64_t OT_len, channel* chan);
	//uint64_t** m_vCodeWords;

	// performs all the OOS specific tasks:
	// - exchange additional OTs
	// - send random weights to receiver (as a seed)
	// - calculate + receive + control checksums
	// returns true if checksum OK, otherwise the protocol should not continue!
	bool OOSCheck(vector<CBitVector *> &Q_list, channel *chan, uint64_t internal_numOTs, uint64_t firstOTid);

	uint32_t m_nAdditionalOTs;
};



#endif /* OOS_OT_EXT_SENDER_H_ */

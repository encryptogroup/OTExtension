#ifndef KOS_OT_EXTENSION_RECEIVER_H_
#define KOS_OT_EXTENSION_RECEIVER_H_

#include "ot-ext-rec.h"
#include "carryless-multiplication.h"

class KOSOTExtRec : public OTExtRec {

public:

	// the optional parameter s specifies the amount of additional OTs which is number-of-base-OTs + s
	// so normally, KOS15 performs 128 + 64 = 192 additional OTs
	KOSOTExtRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint64_t s = 64) {
		InitRec(crypt, rcvthread, sndthread, crypt->get_seclvl().symbits);
		m_nAdditionalOTs = m_nBaseOTs + s;
	}
	;


	virtual ~KOSOTExtRec() {}	;

	BOOL receiver_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);

private:
	// calculate checksum for numOTs rows of T and choice bits and add them to result.
	// the necessary weights are generated with weights_prf_state.
	// the choice bits are taken from the given vector at the given offset
	void calculateChecksum(CBitVector *T, prf_state_ctx *weights_prf_state, CBitVector *choices, uint64_t choicesOffset, uint8_t *tCheck, uint8_t *xCheck, uint64_t numOTs);

	// completely handle the additional OTs including checksum calculation
	// firstOTid is the id of the first OT handled by the current thread. It is necessary
	// to create unique ids for the additional OTs.
	void handleAdditionalOTs(channel *chan, prf_state_ctx *weights_prf_state, uint8_t *tCheck, uint8_t *xCheck, uint64_t firstOTid);

	// a version of MaskBaseOTs that works on a different choice vector
	// the choice vector must contain at least m_nAdditionalOTs Bits
	void AdditionalMaskBaseOTs(CBitVector* T, CBitVector* SndBuf, CBitVector *choices, uint64_t numblocks);



	uint64_t m_nAdditionalOTs;
};

#endif /* KOS_OT_EXTENSION_RECEIVER_H_ */

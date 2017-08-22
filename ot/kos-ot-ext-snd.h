#ifndef KOS_OT_EXT_SENDER_H_
#define KOS_OT_EXT_SENDER_H_

#include "ot-ext-snd.h"

class KOSOTExtSnd : public OTExtSnd {

public:

	// the optional parameter s specifies the amount of additional OTs which is number-of-base-OTs + s
	// so normally, KOS15 performs 128 + 64 = 192 additional OTs
	KOSOTExtSnd(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint64_t s = 64) {
		InitSnd(crypt, rcvthread, sndthread, crypt->get_seclvl().symbits);
		m_nAdditionalOTs = m_nBaseOTs + s;
	}
	;


	virtual ~KOSOTExtSnd() {	};

	BOOL sender_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);

private:

	// calculate checksum for numOTs rows of Q and add them to result.
	// the necessary weights are generated with weights_prf_state.
	void calculateChecksum(CBitVector *Q, prf_state_ctx *weights_prf_state, uint8_t *qCheck, uint64_t numOTs);

	// completely handle the additional OTs including checksum calculation
	// firstOTid is the id of the first OT handled by the current thread. It is necessary
	// to create unique ids for the additional OTs.
	void handleAdditionalOTs(channel *chan, prf_state_ctx *weights_prf_state, uint8_t *qCheck, uint64_t firstOTid);

	// receive and check checksums from receiver.
	// returns true if OK. Protocol must be aborted if false is returned!
	bool controlChecksum(uint8_t *qCheck, channel *chan);


	uint64_t m_nAdditionalOTs;

};



#endif /* KOS_OT_EXT_SENDER_H_ */

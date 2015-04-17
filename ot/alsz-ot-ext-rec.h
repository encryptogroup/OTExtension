/*
 * alsz-ot-ext-rec.h
 *
 *  Created on: Mar 23, 2015
 *      Author: mzohner
 *
 * Malicious OT extension routine from ALSZ15
 */

#ifndef ALSZ_OT_EXT_REC_H_
#define ALSZ_OT_EXT_REC_H_

#include "ot-ext-rec.h"


typedef struct rcv_check_ctx {
	uint64_t otid;
	uint64_t numblocks;
	uint8_t* T0;
	uint8_t* T1;
} rcv_check_t;

class ALSZOTExtRec : public OTExtRec {
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
	ALSZOTExtRec(uint32_t nSndVals, crypto* crypt, RcvThread* rcvthread, SndThread* sndthread,
			uint32_t nbaseots, uint32_t nchecks, bool dobaseots=false) {
		InitRec(nSndVals, crypt, rcvthread, sndthread, nbaseots);
		m_nChecks = nchecks;
		m_bDoBaseOTs=dobaseots;
	}
	;


	~ALSZOTExtRec() {
	}
	;

	BOOL receiver_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);

private:
	rcv_check_t EnqueueSeed(uint8_t* T0, uint8_t* T1, uint64_t otid, uint64_t numblocks);
	void ComputeOWF(queue<rcv_check_t>* check_buf_q, channel* check_chan);
	void ReceiveAndFillMatrix(uint64_t** rndmat, channel* mat_chan);
	bool m_bDoBaseOTs;
};

#endif /* ALSZ_OT_EXT_REC_H_ */

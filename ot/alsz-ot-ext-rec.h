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
#include "alsz-ot-ext-snd.h"
#include "xormasking.h"
#include "simpleot.h"


typedef struct alsz_rcv_check_ctx {
	uint64_t otid;
	uint64_t numblocks;
	uint8_t* T0;
	uint8_t* T1;
} alsz_rcv_check_t;

class ALSZOTExtRec : public OTExtRec {

public:
	ALSZOTExtRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread,
			uint32_t nbaseots, uint32_t nchecks) {
		InitRec(crypt, rcvthread, sndthread, nbaseots);
		m_nChecks = nchecks;
		m_bDoBaseOTs=false;
		//m_tBaseOTQ.resize(0);// = new vector<base_ots_snd_t>;// = new vector<base_ots_sndt>();
	}
	;


	~ALSZOTExtRec() {}	;

	BOOL receiver_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);

	/*void setBaseOTs(base_ots_snd_t** baseOTKeys, uint32_t num_keys) {
		for(uint32_t i = 0; i < num_keys; i++)
			m_tBaseOTQ.push_back(baseOTKeys[i]);
	}*/
	void computePKBaseOTs() {
		m_bDoBaseOTs = true;
	}

private:
	alsz_rcv_check_t EnqueueSeed(uint8_t* T0, uint8_t* T1, uint64_t otid, uint64_t numblocks);
	void ComputeOWF(queue<alsz_rcv_check_t>* check_buf_q, channel* check_chan);
	void ReceiveAndFillMatrix(uint64_t** rndmat, channel* mat_chan);

	//vector<base_ots_snd_t*> m_tBaseOTQ;
	bool m_bDoBaseOTs;
};

#endif /* ALSZ_OT_EXT_REC_H_ */

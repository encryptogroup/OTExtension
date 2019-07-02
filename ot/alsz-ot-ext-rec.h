/**
 \file 		alsz-ot-rec.h
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 ENCRYPTO Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief	    Malicious OT extension routine from ALSZ15
 */

#ifndef ALSZ_OT_EXT_REC_H_
#define ALSZ_OT_EXT_REC_H_

#include "ot-ext-rec.h"


typedef struct alsz_rcv_check_ctx {
	uint64_t otid;
	uint64_t numblocks;
	uint8_t* T0;
	uint8_t* T1;
} alsz_rcv_check_t;

class ALSZOTExtRec : public OTExtRec {

public:
	ALSZOTExtRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread,
			uint32_t nbaseots, uint32_t nchecks, uint64_t num_ot_blocks=4096, bool verify_ot=true, bool use_fixed_key_aes_hashing=false)
		: OTExtRec(num_ot_blocks, verify_ot, use_fixed_key_aes_hashing) {
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
	void ComputeOWF(std::queue<alsz_rcv_check_t>* check_buf_q, channel* check_chan);
	void ReceiveAndFillMatrix(uint64_t** rndmat, channel* mat_chan);

	//vector<base_ots_snd_t*> m_tBaseOTQ;
	bool m_bDoBaseOTs;
};

#endif /* ALSZ_OT_EXT_REC_H_ */

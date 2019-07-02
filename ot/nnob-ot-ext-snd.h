/**
 \file 		nnob-ot-ext-snd.h
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
 \brief		Malicious OT extension routine from NNOB12
 */

#ifndef NNOB_OT_EXT_SND_H_
#define NNOB_OT_EXT_SND_H_

#include "ot-ext-snd.h"

typedef struct nnob_snd_check_ctx {
	uint64_t otid;
	uint64_t numblocks;
	linking_t* perm;
	uint8_t* chk_buf;
	uint8_t* permchoicebits;
} nnob_snd_check_t;

class NNOBOTExtSnd : public OTExtSnd {

public:
	NNOBOTExtSnd( crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, bool dobaseots=true, uint64_t num_ot_blocks=4096, bool verify_ot=true, bool use_fixed_key_aes_hashing=false)
		: OTExtSnd(num_ot_blocks, verify_ot, use_fixed_key_aes_hashing) {
		uint32_t nbaseots = ceil_divide(crypt->get_seclvl().symbits * 8, 3);
		InitSnd(crypt, rcvthread, sndthread, nbaseots);
		m_nChecks = nbaseots / 2;
		m_bDoBaseOTs = dobaseots;
	}
	;


	~NNOBOTExtSnd() {
	}
	;

	BOOL sender_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);


private:
	nnob_snd_check_t* UpdateCheckBuf(uint8_t* tocheckseed, uint8_t* tocheckrcv, uint64_t otid, uint64_t numblocks, channel* check_chan);
	void XORandOWF(uint8_t* idaptr, uint8_t* idbptr, uint64_t rowbytelen, uint8_t* tmpbuf, uint8_t* resbuf, uint8_t* hash_buf);
	void genRandomMapping(linking_t* outperm, uint32_t nids);
	BOOL CheckConsistency(std::queue<nnob_snd_check_t*>* check_buf_q, channel* check_chan);
	void FillAndSendRandomMatrix(uint64_t **rndmat, channel* chan);

	bool m_bDoBaseOTs;
};

#endif /* NNOB_OT_EXT_SND_H_ */

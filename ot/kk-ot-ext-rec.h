/**
 \file 		kk-ot-ext-rec.h
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
 \brief
 */


#ifndef KK_OT_EXTENSION_RECEIVER_H_
#define KK_OT_EXTENSION_RECEIVER_H_

#include "ot-ext-rec.h"
#include "kk-ot-ext.h"

class KKOTExtRec : public OTExtRec, public KKOTExt {

public:
	KKOTExtRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint64_t num_ot_blocks=4096, bool verify_ot=true, bool use_fixed_key_aes_hashing=false)
		: OTExtRec(num_ot_blocks, verify_ot, use_fixed_key_aes_hashing) {
		uint32_t numbaseots = 2*crypt->get_seclvl().symbits;//, pad_to_power_of_two(nSndVals));

		//assert(pad_to_power_of_two(nSndVals) == nSndVals); //TODO right now only supports power of two nSndVals
		assert(numbaseots == 256); //TODO: right now only 256 base OTs work due to the size of the code
		InitRec(crypt, rcvthread, sndthread, 2*crypt->get_seclvl().symbits);


		//Initialize the code words
		InitAndReadCodeWord(&m_vCodeWords);
	}
	;


	virtual ~KKOTExtRec() {
		//TODO
		//free(m_vKeySeedMtx);
	}
	;

	BOOL receiver_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);

private:
	void GenerateChoiceCodes(CBitVector* choicecodes, CBitVector* vSnd, CBitVector* T, uint32_t startpos, uint32_t len);
	void KKSetOutput(CBitVector* maskbuf, uint64_t otid, uint64_t otlen, std::queue<mask_block*>* mask_queue, channel* chan);
	void KKHashValues(CBitVector* T, CBitVector* seedbuf, CBitVector* maskbuf, uint64_t OT_ptr, uint64_t OT_len, uint64_t** mat_mul);
	void KKMaskBaseOTs(CBitVector* T, CBitVector* SndBuf, uint64_t numblocks);
	void KKReceiveAndUnMask(channel* chan, std::queue<mask_block*>* mask_queue);
	//uint64_t** m_vCodeWords;
};

#endif /* KK_OT_EXTENSION_RECEIVER_H_ */

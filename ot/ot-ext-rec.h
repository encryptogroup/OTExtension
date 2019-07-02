/**
 \file 		ot-ext-rec.h
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

#ifndef OT_EXTENSION_RECEIVER_H_
#define OT_EXTENSION_RECEIVER_H_

#include "ot-ext.h"

class channel;
class CBitVector;

class OTExtRec : public OTExt {

public:

	OTExtRec(uint64_t num_ot_blocks, bool verify_ot, bool use_fixed_key_aes_hashing)
		: OTExt(num_ot_blocks, verify_ot, use_fixed_key_aes_hashing) {};
	virtual ~OTExtRec(){
		// TODO: nsndvals is currently hardcoeded in OTExtRec::ComputePKBaseOTs()
		// maybe add it as a private attribute to class OTExt and move the
		// following loop to its destructor?
		uint32_t nsndvals = 2;
		for(uint32_t i = 0; i < m_tBaseOTKeys.size(); i++) {
			for(uint32_t j = 0; j < m_nBaseOTs * nsndvals; j++) {
				m_cCrypt->clean_aes_key(&m_tBaseOTKeys[i][j]);
			}
			free(m_tBaseOTKeys[i]);
		}
	};
	BOOL receive(uint64_t numOTs, uint64_t bitlength, uint64_t nsndvals, CBitVector* choices, CBitVector* ret,
			snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numThreads, MaskingFunction* maskfct);

	virtual void ComputeBaseOTs(field_type ftype) = 0;
protected:

	BOOL start_receive(uint32_t numThreads);

	virtual BOOL receiver_routine(uint32_t threadid, uint64_t numOTs) = 0;

	void InitRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t nbaseOTs) {
		Init(crypt, rcvthread, sndthread, nbaseOTs);
	}
	;

	//void ReceiveAndProcess(uint32_t numThreads);
	void BuildMatrices(CBitVector* T, CBitVector* SndBuf, uint64_t ctr, uint64_t numblocks, OT_AES_KEY_CTX* seedkeyptr);
	void MaskBaseOTs(CBitVector* T, CBitVector* SndBuf, uint64_t OTid, uint64_t numblocks);
	void SendMasks(CBitVector* Sndbuf, channel* chan, uint64_t OTid, uint64_t processedOTs, uint64_t rem_row = 1);
	void HashValues(CBitVector* T, CBitVector* seedbuf, CBitVector* maskbuf, uint64_t ctr, uint64_t lim, uint64_t** mat);
	void SetOutput(CBitVector* maskbuf, uint64_t otid, uint64_t otlen, std::queue<mask_block*>* mask_queue, channel* chan);
	void ReceiveAndUnMask(channel* chan, std::queue<mask_block*>* mask_queue);
	void ReceiveAndXORCorRobVector(CBitVector* T, uint64_t OT_len, channel* chan);
	BOOL verifyOT(uint64_t myNumOTs);

	//void CleanupReceiver() { Cleanup();  };//TODO check if necessary and implement

	CBitVector* m_vChoices;
	CBitVector* m_vRet;
	//CBitVector m_vTempOTMasks;

	void ComputePKBaseOTs();

	class OTReceiverThread: public CThread {
	public:
		OTReceiverThread(uint32_t threadid, uint64_t nOTs, OTExtRec* ext) {
			receiverID = threadid;
			numOTs = nOTs;
			callback = ext;
			success = false;
		}
		;
		~OTReceiverThread() {
		}
		;
		void ThreadMain() {
			success = callback->receiver_routine(receiverID, numOTs);
		}
		;
	private:
		uint32_t receiverID;
		uint64_t numOTs;
		OTExtRec* callback;
		BOOL success;
	};
};

#endif /* OT_EXTENSION_RECEIVER_H_ */

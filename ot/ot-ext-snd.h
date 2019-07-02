/**
 \file 		ot-ext-snd.h
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

#ifndef OT_EXTENSION_SENDER_H_
#define OT_EXTENSION_SENDER_H_

#include "ot-ext.h"
#include <vector>

class channel;

class OTExtSnd : public OTExt {

public:
	OTExtSnd(uint64_t num_ot_blocks, bool verify_ot, bool use_fixed_key_aes_hashing)
		: OTExt(num_ot_blocks, verify_ot, use_fixed_key_aes_hashing) {};

	virtual ~OTExtSnd() {
		for(size_t i = 0; i < m_tBaseOTChoices.size(); i++) {
			delete m_tBaseOTChoices[i];
		}
		// TODO: This could be done in OTExt destructor;
		// see also comment in OTExtSnd destructor
		for(uint32_t i = 0; i < m_tBaseOTKeys.size(); i++) {
			for(uint32_t j = 0; j < m_nBaseOTs; j++) {
				m_cCrypt->clean_aes_key(&m_tBaseOTKeys[i][j]);
			}
			free(m_tBaseOTKeys[i]);
		}
		// do not free(m_vValues), since it is passed from the outside to send()
	};

	BOOL send(uint64_t numOTs, uint64_t bitlength, uint64_t nsndvals, CBitVector** X, snd_ot_flavor stype,
			rec_ot_flavor rtype, uint32_t numThreads, MaskingFunction* maskfct);

	virtual void ComputeBaseOTs(field_type ftype) = 0;
protected:
	void InitSnd(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t nbaseOTs) {
		Init(crypt, rcvthread, sndthread, nbaseOTs);

		m_tBaseOTChoices.resize(0);
	}
	;

	BOOL start_send(uint32_t numThreads);
	virtual BOOL sender_routine(uint32_t threadid, uint64_t numOTs) = 0;

	BOOL OTSenderRoutine(uint32_t id, uint32_t myNumOTs);

	void BuildQMatrix(CBitVector* T, uint64_t ctr, uint64_t blocksize, OT_AES_KEY_CTX* seedkeyptr);
	void UnMaskBaseOTs(CBitVector* T, CBitVector* RcvBuf, CBitVector* U, uint64_t numblocks);
	void MaskAndSend(CBitVector* snd_buf, uint64_t progress, uint64_t processedOTs, channel* chan);
	//void SendBlocks(uint32_t numThreads);
	void ReceiveMasks(CBitVector* vRcv, channel* chan, uint64_t processedOTs, uint64_t rec_r_ot_startpos=1);
	void GenerateSendAndXORCorRobVector(CBitVector* Q, uint64_t OT_len, channel* chan);
	void HashValues(CBitVector* Q, CBitVector* seedbuf, CBitVector* snd_buf, CBitVector* Uptr, uint64_t ctr, uint64_t processedOTs,  uint64_t** mat);
	BOOL verifyOT(uint64_t myNumOTs);

	void ComputePKBaseOTs();

	//CBitVector m_vU;
	CBitVector** m_vValues;

	BYTE* m_vSeed;

    std::vector<CBitVector*> m_tBaseOTChoices;


	class OTSenderThread: public CThread {
	public:
		OTSenderThread(uint32_t id, uint64_t nOTs, OTExtSnd* ext) {
			senderID = id;
			numOTs = nOTs;
			callback = ext;
			success = false;
		}
		;
		~OTSenderThread() {
		}
		;
		void ThreadMain() {
			success = callback->sender_routine(senderID, numOTs);
		}
		;
	private:
		uint32_t senderID;
		uint64_t numOTs;
		OTExtSnd* callback;
		BOOL success;
	};

};




#endif /* OT_EXTENSION_SENDER_H_ */

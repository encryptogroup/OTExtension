/*
 * ot-extension-sender.h
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */

#ifndef OT_EXTENSION_SENDER_H_
#define OT_EXTENSION_SENDER_H_

#include "ot-ext.h"

class OTExtSnd : public OTExt {
	/*
	 * OT sender part
	 * Input:
	 * ret: returns the resulting bit representations. Has to initialized to a byte size of: nOTs * nSndVals * state.field_size
	 *
	 * CBitVector* values: holds the values to be transferred. If C_OT is enabled, the first dimension holds the value while the delta is written into the second dimension
	 * Output: was the execution successful?
	 */
public:
	OTExtSnd() {};

	virtual ~OTExtSnd() {
		//for(uint32_t i = 0; i < m_tBaseOTChoices.size(); i++)
		//	m_tBaseOTChoices[i]->delCBitVector();
		m_tBaseOTChoices.clear();

		free(m_vValues);
	};

	BOOL send(uint64_t numOTs, uint64_t bitlength, uint64_t nsndvals, CBitVector** X, snd_ot_flavor stype,
			rec_ot_flavor rtype, uint32_t numThreads, MaskingFunction* maskfct);

	virtual void ComputeBaseOTs(field_type ftype) = 0;
protected:
	void InitSnd(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t nbaseOTs) {
		Init(crypt, rcvthread, sndthread, nbaseOTs, nbaseOTs);

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

	vector<CBitVector*> m_tBaseOTChoices;


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

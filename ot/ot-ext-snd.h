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

	BOOL send(uint32_t numOTs, uint32_t bitlength, CBitVector& s0, CBitVector& s1, snd_ot_flavor stype,
			rec_ot_flavor rtype, uint32_t numThreads, MaskingFunction* maskfct);

	virtual void ComputeBaseOTs(field_type ftype) = 0;
protected:
	void InitSnd(uint32_t nSndVals, crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t nbaseOTs) {
		Init(nSndVals, crypt, rcvthread, sndthread, nbaseOTs, nbaseOTs);
		m_vU.Create(nbaseOTs, crypt);
		//m_vU.Copy(U.GetArr(), 0, bits_in_bytes(nbaseOTs));
		//for (int i = nbaseOTs; i < PadToMultiple(nbaseOTs, 8); i++)
		//	m_vU.SetBit(i, 0);

		m_vValues = (CBitVector*) malloc(sizeof(CBitVector) * nSndVals);
	}
	;

	BOOL start_send(uint32_t numThreads);
	virtual BOOL sender_routine(uint32_t threadid, uint64_t numOTs) = 0;

	BOOL OTSenderRoutine(uint32_t id, uint32_t myNumOTs);

	void BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint64_t ctr, uint64_t blocksize);
	void UnMaskBaseOTs(CBitVector& T, CBitVector& RcvBuf, uint64_t numblocks);
	void MaskAndSend(CBitVector* snd_buf, uint64_t progress, uint64_t processedOTs, channel* chan);
	//void SendBlocks(uint32_t numThreads);
	void HashValues(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint64_t ctr, uint64_t processedOTs);
	BOOL verifyOT(uint64_t myNumOTs);

	void ComputePKBaseOTs();

	CBitVector m_vU;
	CBitVector* m_vValues;

	BYTE* m_vSeed;

#ifdef FIXED_KEY_AES_HASHING
	AES_KEY_CTX* m_kCRFKey;
#endif

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

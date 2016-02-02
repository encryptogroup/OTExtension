/*
 * ot-extension-receiver.h
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */

#ifndef OT_EXTENSION_RECEIVER_H_
#define OT_EXTENSION_RECEIVER_H_

#include "ot-ext.h"


class OTExtRec : public OTExt {
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

	OTExtRec(){};
	virtual ~OTExtRec(){};
	BOOL receive(uint64_t numOTs, uint64_t bitlength, uint64_t nsndvals, CBitVector* choices, CBitVector* ret,
			snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numThreads, MaskingFunction* maskfct);

	virtual void ComputeBaseOTs(field_type ftype) = 0;
protected:

	BOOL start_receive(uint32_t numThreads);

	virtual BOOL receiver_routine(uint32_t threadid, uint64_t numOTs) = 0;

	void InitRec(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t nbaseOTs) {
		Init(crypt, rcvthread, sndthread, nbaseOTs, 2*nbaseOTs);
	}
	;

	//void ReceiveAndProcess(uint32_t numThreads);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint64_t ctr, uint64_t numblocks, OT_AES_KEY_CTX* seedkeyptr);
	void MaskBaseOTs(CBitVector& T, CBitVector& SndBuf, uint64_t OTid, uint64_t numblocks);
	void SendMasks(CBitVector Sndbuf, channel* chan, uint64_t OTid, uint64_t processedOTs, uint64_t rem_row = 1);
	void HashValues(CBitVector* T, CBitVector* seedbuf, CBitVector* maskbuf, uint64_t ctr, uint64_t lim, uint64_t** mat);
	void SetOutput(CBitVector* maskbuf, uint64_t otid, uint64_t otlen, queue<mask_block*>* mask_queue, channel* chan);
	void ReceiveAndUnMask(channel* chan, queue<mask_block*>* mask_queue);
	void ReceiveAndXORCorRobVector(CBitVector& T, uint64_t OT_len, channel* chan);
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

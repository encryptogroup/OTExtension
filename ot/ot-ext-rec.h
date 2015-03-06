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
	BOOL receive(uint64_t numOTs, uint64_t bitlength, CBitVector& choices, CBitVector& ret,
			eot_flavor type, uint32_t numThreads, MaskingFunction* maskfct);


protected:

	BOOL start_receive(uint32_t numThreads);

	virtual BOOL receiver_routine(uint32_t threadid, uint64_t numOTs) = 0;

	void InitRec(uint32_t nSndVals, crypto* crypt, CSocket* sock, BYTE* keybytes, uint32_t nbaseOTs) {
		Init(nSndVals, crypt, sock, keybytes, nbaseOTs, nSndVals * nbaseOTs);
	}
	;

	//void ReceiveAndProcess(uint32_t numThreads);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint64_t numblocks, uint64_t ctr);
	void HashValues(CBitVector& T, CBitVector& seedbuf, uint64_t ctr, uint64_t lim);
	void ReceiveAndUnMask(queue<uint8_t*> *rcvqueue);
	BOOL verifyOT(uint64_t myNumOTs);


	void Cleanup() {};//TODO check if necessary and implement

	CBitVector m_nChoices;
	CBitVector m_nRet;
	CBitVector m_vTempOTMasks;


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

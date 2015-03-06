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

	/*OTExtSnd(uint32_t nSndVals, uint32_t nOTs, uint32_t bitlength, crypto* crypt, CSocket* sock, CBitVector& U, BYTE* keybytes, CBitVector& x0, CBitVector& x1, BYTE type,
			int nbaseOTs = -1, int nchecks = -1, int nbaseseeds = -1) {
		Init(nSndVals, crypt, sock, U, keybytes, nbaseOTs, nchecks, nbaseseeds);
		m_nOTs = nOTs;
		m_vValues[0] = x0;
		m_vValues[1] = x1;
		m_nBitLength = bitlength;
		m_bProtocol = type;
	}
	;*/
	BOOL send(uint32_t numOTs, uint32_t bitlength, CBitVector& s0, CBitVector& s1, eot_flavor type, uint32_t numThreads, MaskingFunction* maskfct);

protected:
	void InitSnd(uint32_t nSndVals, crypto* crypt, CSocket* sock, CBitVector& U, BYTE* keybytes, uint32_t nbaseOTs) {
		Init(nSndVals, crypt, sock, keybytes, nbaseOTs, nbaseOTs);
		m_vU.Create(nbaseOTs);
		m_vU.Copy(U.GetArr(), 0, bits_in_bytes(nbaseOTs));
		for (int i = nbaseOTs; i < PadToMultiple(nbaseOTs, 8); i++)
			m_vU.SetBit(i, 0);

		m_vValues = (CBitVector*) malloc(sizeof(CBitVector) * nSndVals);
	}
	;

	/*void InitSnd(uint32_t nSndVals, crypto* crypt, CSocket* sock, CBitVector& U, BYTE* keybytes, int nbaseOTs, int nchecks, int nbaseseeds) {
		m_nSndVals = nSndVals;
		m_vSockets = sock;
		m_nCounter = 0;
		m_cCrypt = crypt;
		m_nSymSecParam = m_cCrypt->get_seclvl().symbits;
		m_nBaseOTs = m_nSymSecParam;

		if (nbaseOTs != -1)
			m_nBaseOTs = nbaseOTs;

		int keyseeds = m_nBaseOTs;
		if (nbaseseeds != -1)
			keyseeds = nbaseseeds;

		m_vU.Create(keyseeds);
		m_vU.Copy(U.GetArr(), 0, ceil_divide(keyseeds, 8));
		for (int i = keyseeds; i < PadToMultiple(keyseeds, 8); i++)
			m_vU.SetBit(i, 0);

		m_vValues = (CBitVector*) malloc(sizeof(CBitVector) * nSndVals);
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * keyseeds);
		m_lSendLock = new CLock;

		InitAESKey(m_vKeySeeds, keybytes, keyseeds, m_cCrypt);

#ifdef FIXED_KEY_AES_HASHING
		m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		m_cCrypt->init_aes_key(m_kCRFKey, (uint8_t*) fixed_key_aes_seed);
#endif
	}
	;*/

	BOOL start_send(uint32_t numThreads);
	virtual BOOL sender_routine(uint32_t threadid, uint64_t numOTs) = 0;

	BOOL OTSenderRoutine(uint32_t id, uint32_t myNumOTs);

	void BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint32_t blocksize, uint64_t ctr);
	void MaskAndSend(CBitVector* snd_buf, uint32_t id, uint32_t progress, uint32_t processedOTs);
	//void SendBlocks(uint32_t numThreads);
	void HashValues(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint64_t ctr, uint64_t processedOTs);
	BOOL verifyOT(uint64_t myNumOTs);

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

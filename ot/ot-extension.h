/*
 * Methods for the OT Extension routine
 */

#ifndef __OT_EXTENSION_H_
#define __OT_EXTENSION_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../util/thread.h"
#include "../util/cbitvector.h"
#include "maskingfunction.h"


//#define DEBUG

const BYTE	G_OT = 0x01;
const BYTE 	C_OT = 0x02;
const BYTE	R_OT = 0x03;


static void InitAESKey(AES_KEY_CTX* ctx, BYTE* keybytes, int numkeys)
{
	BYTE* pBufIdx = keybytes;
	for(int i=0; i<numkeys; i++ )
	{
		OTEXT_AES_KEY_INIT(ctx+i, pBufIdx);
		pBufIdx += AES_KEY_BYTES;
	}
}

class OTExtensionSender {
/*
 * OT sender part
 * Input: 
 * ret: returns the resulting bit representations. Has to initialized to a byte size of: nOTs * nSndVals * state.field_size
 * 
 * CBitVector* values: holds the values to be transferred. If C_OT is enabled, the first dimension holds the value while the delta is written into the second dimension
 * Output: was the execution successful?
 */
  public:
	OTExtensionSender(int nSndVals, int nOTs, int bitlength, CSocket* sock, CBitVector& U, BYTE* keybytes, CBitVector& x0, CBitVector& x1,
			CBitVector& delta, BYTE type) {
		m_nSndVals = nSndVals;
		m_nOTs = nOTs; 
		m_nSockets = sock;
		m_nU = U;
		m_vValues[0] = x0;
		m_vValues[1] = x1;
		m_vDelta = delta;
		m_nBitLength = bitlength;
		m_bProtocol = type;
		m_nCounter = 0;
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * NUM_EXECS_NAOR_PINKAS);
		InitAESKey(m_vKeySeeds, keybytes, NUM_EXECS_NAOR_PINKAS);

	};
	OTExtensionSender(int nSndVals, CSocket* sock, CBitVector& U, BYTE* keybytes) {
		m_nSndVals = nSndVals;
		m_nSockets = sock;
		m_nU = U;
		m_nCounter = 0;
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY) * NUM_EXECS_NAOR_PINKAS);
		InitAESKey(m_vKeySeeds, keybytes, NUM_EXECS_NAOR_PINKAS);
	};
	
	~OTExtensionSender(){free(m_vKeySeeds);};
	BOOL send(int numOTs, int bitlength, CBitVector& s0, CBitVector& s1, CBitVector& delta, BYTE type, int numThreads, MaskingFunction* maskfct);

	BOOL send(int numThreads);

	BOOL OTSenderRoutine(int id, int myNumOTs);
	void BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, int blocksize, BYTE* ctr);
	void ProcessAndSend(CBitVector* snd_buf, int id, int progress, int processedOTs);
	void MaskInputs(CBitVector& Q, CBitVector* SndBuf, int ctr, int processedOTs);
	BOOL verifyOT(int myNumOTs);


  private: 
	BYTE m_bProtocol;
  	int m_nSndVals;
  	int m_nOTs;
  	int m_nBitLength;
  	int m_nCounter;
  	CSocket* m_nSockets;
  	CBitVector m_nU;
  	AES_KEY* m_nKeySeeds;
  	CBitVector m_vValues[2];
  	CBitVector m_vDelta;
  	MaskingFunction* m_fMaskFct;
  	AES_KEY_CTX* m_vKeySeeds;

	class OTSenderThread : public CThread {
	 	public:
	 		OTSenderThread(int id, int nOTs, OTExtensionSender* ext) {senderID = id; numOTs = nOTs; callback = ext; success = false;};
			void ThreadMain() {success = callback->OTSenderRoutine(senderID, numOTs);};
		private: 
			int senderID; 
			int numOTs;
			OTExtensionSender* callback;
			BOOL success;
	};

};



class OTExtensionReceiver {
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
	OTExtensionReceiver(int nSndVals, int nOTs, int bitlength,CSocket* sock, BYTE* keybytes, CBitVector& choices, CBitVector& ret,
			BYTE protocol, BYTE* seed) {
		m_nSndVals = nSndVals;
		m_nOTs = nOTs; 
		m_nSockets = sock;
		m_nChoices = choices;
		m_nRet = ret;
		m_nSeed = seed;
		m_nBitLength = bitlength;
		m_bProtocol = protocol;
		m_nCounter = 0;
		m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * NUM_EXECS_NAOR_PINKAS * nSndVals);
		InitAESKey(m_vKeySeedMtx, keybytes, NUM_EXECS_NAOR_PINKAS * nSndVals);
	};
	OTExtensionReceiver(int nSndVals, CSocket* sock, BYTE* keybytes, BYTE* seed) {
		m_nSndVals = nSndVals;
		m_nSockets = sock;
		//m_nKeySeedMtx = vKeySeedMtx;
		m_nSeed = seed;
		m_nCounter = 0;
		m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * NUM_EXECS_NAOR_PINKAS * nSndVals);
		InitAESKey(m_vKeySeedMtx, keybytes, NUM_EXECS_NAOR_PINKAS * nSndVals);
	};
	~OTExtensionReceiver(){free(m_vKeySeedMtx); };


	BOOL receive(int numOTs, int bitlength, CBitVector& choices, CBitVector& ret, BYTE type, int numThreads, MaskingFunction* maskfct);

	BOOL receive(int numThreads);
	BOOL OTReceiverRoutine(int id, int myNumOTs);
	void ReceiveAndProcess(CBitVector& vRcv, int id, int ctr, int lim);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, int numblocks, int ctr, BYTE* ctr_buf);
	void HashValues(CBitVector& T, int ctr, int lim);
	BOOL verifyOT(int myNumOTs);

  private: 
	BYTE m_bProtocol;
  	int m_nSndVals;
  	int m_nOTs;
  	int m_nBitLength;
  	int m_nCounter;
  	CSocket* m_nSockets;
  	CBitVector m_nChoices;
  	CBitVector m_nRet;
  	AES_KEY* m_nKeySeedMtx;
  	BYTE* m_nSeed;
  	MaskingFunction* m_fUnMaskFct;
  	AES_KEY_CTX* m_vKeySeedMtx;

	class OTReceiverThread : public CThread {
	 	public:
	 		OTReceiverThread(int id, int nOTs, OTExtensionReceiver* ext) {receiverID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTReceiverThread(){};
			void ThreadMain() {success = callback->OTReceiverRoutine(receiverID, numOTs);};
		private: 
			int receiverID; 
			int numOTs;
			OTExtensionReceiver* callback;
			BOOL success;
	};

};

#endif

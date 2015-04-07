/**
 \file 		ot-extension.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		Methods for the OT Extension routine
 */

#ifndef __OT_EXTENSION_H_
#define __OT_EXTENSION_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../util/thread.h"
#include "../util/cbitvector.h"
#include "../util/crypto/crypto.h"
#include "maskingfunction.h"
#include "../util/constants.h"
#include "../util/channel.h"
#include "../util/rcvthread.h"
#include "../util/sndthread.h"
#include "naor-pinkas.h"
#include "pvwddh.h"
#include "simpleot.h"


static void InitAESKey(AES_KEY_CTX* ctx, uint8_t* keybytes, uint32_t numkeys, crypto* crypt) {
	BYTE* pBufIdx = keybytes;
	uint32_t aes_key_bytes = crypt->get_aes_key_bytes();
	for (uint32_t i = 0; i < numkeys; i++) {
		crypt->init_aes_key(ctx + i, pBufIdx);
		pBufIdx += aes_key_bytes;
	}
}

struct ot_block {
	uint64_t startotid;
	uint64_t otlen;
	uint8_t* buf;
};

typedef struct {
	uint32_t ida;
	uint32_t idb;
} linking_t;

class OTExt {

public:
	OTExt(){};
	virtual void ComputeBaseOTs(field_type ftype) = 0;

protected:
	void Init(uint32_t nSndVals, crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t nbaseOTs, uint32_t nbasekeys) {
		m_nSndVals = nSndVals;
		m_cCrypt = crypt;
		m_nSymSecParam = m_cCrypt->get_seclvl().symbits;
		m_nBaseOTs = nbaseOTs;
		m_nBlockSizeBits = pad_to_power_of_two(m_nBaseOTs);
		m_nBlockSizeBytes = pad_to_power_of_two(m_nBaseOTs/8);
		m_nCounter = 0;

		//sndthread = new SndThread(sock);
		//rcvthread = new RcvThread(sock);

		//sndthread->Start();
		//rcvthread->Start();
		m_cSndThread = sndthread;
		m_cRcvThread = rcvthread;;

		m_vBaseOTKeys = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * nbasekeys);
	}

	void Cleanup() {
		free(m_vBaseOTKeys);
	}


	void InitPRFKeys(uint8_t* keybytes, uint32_t nbasekeys) {
		InitAESKey(m_vBaseOTKeys, keybytes, nbasekeys, m_cCrypt);

#ifdef FIXED_KEY_AES_HASHING
		m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
		m_cCrypt->init_aes_key(m_kCRFKey, (uint8_t*) fixed_key_aes_seed);
#endif
	}

	snd_ot_flavor m_eSndOTFlav;
	rec_ot_flavor m_eRecOTFlav;
	uint32_t m_nSndVals;
	uint64_t m_nOTs;
	uint64_t m_nBitLength;
	uint64_t m_nCounter;
	uint32_t m_nSymSecParam;
	uint32_t m_nBaseOTs;
	uint32_t m_nChecks;
	uint32_t m_nBlockSizeBits;
	uint32_t m_nBlockSizeBytes;

	crypto* m_cCrypt;

	SndThread* m_cSndThread;
	RcvThread* m_cRcvThread;

	AES_KEY_CTX* m_vBaseOTKeys;

	MaskingFunction* m_fMaskFct;

	BaseOT* m_cBaseOT;


#ifdef FIXED_KEY_AES_HASHING
	AES_KEY_CTX* m_kCRFKey;
#endif
};




#ifdef FIXED_KEY_AES_HASHING
static const uint8_t fixed_key_aes_seed[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
#endif



#define OWF_BYTES AES_BYTES



#ifdef FIXED_KEY_AES_HASHING
inline void FixedKeyHashing(AES_KEY_CTX* aeskey, BYTE* outbuf, BYTE* inbuf, BYTE* tmpbuf, uint64_t id, uint32_t bytessecparam, crypto* crypt) {
#ifdef HIGH_SPEED_ROT_LT
	((uint64_t*) tmpbuf)[0] = id ^ ((uint64_t*) inbuf)[0];
	((uint64_t*) tmpbuf)[1] = ((uint64_t*) inbuf)[1];
#else
	memset(tmpbuf, 0, AES_BYTES);
	memcpy(tmpbuf, (BYTE*) (&id), sizeof(int));

	for (int i = 0; i < bytessecparam; i++) {
		tmpbuf[i] = tmpbuf[i] ^ inbuf[i];
	}
#endif

	crypt->encrypt(aeskey, outbuf, tmpbuf, AES_BYTES);

#ifdef HIGH_SPEED_ROT_LT
	((uint64_t*) outbuf)[0] ^= ((uint64_t*) inbuf)[0];
	((uint64_t*) outbuf)[1] ^= ((uint64_t*) inbuf)[1];
#else
	for (int i = 0; i < bytessecparam; i++) {
		outbuf[i] = outbuf[i] ^ inbuf[i];
	}
#endif
}
#endif



#endif /* __OT_EXTENSION_H_ */

/**
 \file 		ot-ext.h
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
 \brief     Methods for the OT Extension routine
 */

#ifndef __OT_EXTENSION_H_
#define __OT_EXTENSION_H_

//internal OT options
//#define OTTiming
//#define AES_OWF
//#define GENERATE_T_EXPLICITELY //send two instead of only one message, only required for benchmarking, not recommended
//#define DEBUG_OT_HASH_IN
//#define DEBUG_OT_HASH_OUT
//#define DEBUG_OT_SEED_EXPANSION
//#define DEBUG_BASE_OT_HASH_RET
//#define DEBUG_RECEIVE_THREAD
//#define DEBUG_SEND_THREAD
//#define HIGH_SPEED_ROT_LT
//#define DEBUG_ALSZ_CHECKS
//#define DEBUG_ALSZ_CHECKS_INPUT
//#define DEBUG_ALSZ_CHECKS_OUTPUT
//#define DEBUG_NNOB_CHECKS
//#define DEBUG_NNOB_CHECKS_INPUT
//#define DEBUG_NNOB_CHECKS_OUTPUT
//#define DEBUG_KK_OTBREAKDOWN


#include "maskingfunction.h"
#include <ENCRYPTO_utils/rcvthread.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/utils.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include "OTconstants.h"
#include <cstring>

#ifdef OTTiming
#include <iostream>
#include <ENCRYPTO_utils/timer.h>
#endif

class BaseOT;
class CBitVector;

#ifdef USE_PIPELINED_AES_NI
	typedef ROUND_KEYS OT_AES_KEY_CTX;

	static void InitAESKey(OT_AES_KEY_CTX* ctx, uint8_t* keybytes, uint32_t numkeys, crypto* crypt) {
		intrin_sequential_ks4(ctx, keybytes, numkeys);
	}
#else
	typedef AES_KEY_CTX OT_AES_KEY_CTX;

static const uint8_t fixed_key_aes_seed[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

	static void InitAESKey(OT_AES_KEY_CTX* ctx, uint8_t* keybytes, uint32_t numkeys, crypto* crypt) {
		BYTE* pBufIdx = keybytes;
		uint32_t aes_key_bytes = crypt->get_aes_key_bytes();
		for (uint32_t i = 0; i < numkeys; i++) {
			crypt->init_aes_key(ctx + i, pBufIdx);
			pBufIdx += aes_key_bytes;
		}
	}
#endif




struct ot_block {
	uint64_t startotid;
	uint64_t otlen;
	uint8_t* buf;
};

struct mask_block {
	uint64_t startotid;
	uint64_t otlen;
	CBitVector* buf;
};

typedef struct {
	uint32_t ida;
	uint32_t idb;
} linking_t;



typedef struct mask_buf_ctx {
	uint64_t otid;
	uint64_t otlen;
	CBitVector* maskbuf;
} mask_buf_t;




class OTExt {

public:
	OTExt(uint64_t num_ot_blocks, bool verify_ot, bool use_fixed_key_aes_hashing)
		: num_ot_blocks(num_ot_blocks), buffer_ot_keys(num_ot_blocks),
		  verify_ot(verify_ot),
		  use_fixed_key_aes_hashing(use_fixed_key_aes_hashing) {};
	virtual ~OTExt() {
		if (use_fixed_key_aes_hashing) {
			m_cCrypt->clean_aes_key(m_kCRFKey);
			free(m_kCRFKey);
		}
	};

	virtual void ComputeBaseOTs(field_type ftype) = 0;

	void EnableMinEntCorrRobustness() {
		m_bUseMinEntCorRob = true;
	}
	void DisableMinEntCorrRobustness() {
		m_bUseMinEntCorRob = false;
	}

protected:
	void Init(crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t nbaseOTs) {
		m_cCrypt = crypt;
		m_nSymSecParam = m_cCrypt->get_seclvl().symbits;
		m_nBaseOTs = nbaseOTs;
		m_nBlockSizeBits = pad_to_power_of_two(m_nBaseOTs);
		m_nBlockSizeBytes = pad_to_power_of_two(m_nBaseOTs/8);
		m_nCounter = 0;
		m_bUseMinEntCorRob = false;
		m_tBaseOTKeys.resize(0);

		//sndthread = new SndThread(sock);
		//rcvthread = new RcvThread(sock);

		//sndthread->Start();
		//rcvthread->Start();
		m_cSndThread = sndthread;
		m_cRcvThread = rcvthread;;

		//m_vBaseOTKeys = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * nbasekeys);
	}


	void InitPRFKeys(OT_AES_KEY_CTX* base_ot_keys, uint8_t* keybytes, uint32_t nbasekeys) {
		InitAESKey(base_ot_keys, keybytes, nbasekeys, m_cCrypt);

		if (use_fixed_key_aes_hashing) {
			m_kCRFKey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
			m_cCrypt->init_aes_key(m_kCRFKey, (uint8_t*) fixed_key_aes_seed);
		}
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

	//The flag whether to use min-entropy correlation robustness instead of correlation robustness
	bool m_bUseMinEntCorRob;

	SndThread* m_cSndThread;
	RcvThread* m_cRcvThread;

    std::vector<OT_AES_KEY_CTX*> m_tBaseOTKeys;

	MaskingFunction* m_fMaskFct;

	BaseOT* m_cBaseOT;

	// (previously compile time options)
	const uint64_t num_ot_blocks;
	const uint64_t buffer_ot_keys;
	const bool verify_ot;
	const bool use_fixed_key_aes_hashing;

	AES_KEY_CTX* m_kCRFKey;
};

inline void fillRndMatrix(uint8_t* seed, uint64_t** mat, uint64_t cols, uint64_t rows, crypto* crypt) {
	uint32_t columnlen = ceil_divide(cols, sizeof(uint64_t) * 8);
	prf_state_ctx tmpstate;
	crypt->init_prf_state(&tmpstate, seed);
	for(uint32_t i = 0; i < rows; i++) {
		gen_rnd_bytes(&tmpstate, (uint8_t*) mat[i], columnlen * sizeof(uint64_t));
	}
	crypt->free_prf_state(&tmpstate);
}

inline void initRndMatrix(uint64_t*** mat, uint64_t cols, uint64_t rows) {
	uint32_t columnlen = ceil_divide(cols, sizeof(uint64_t) * 8);
	*mat = (uint64_t**) malloc(sizeof(uint64_t*) * rows);
	for(uint32_t i = 0; i < rows; i++) {
		(*mat)[i] = (uint64_t*) malloc(sizeof(uint64_t) * columnlen);
	}}

inline void freeRndMatrix(uint64_t** mat, uint32_t nrows) {
	for(uint32_t i = 0; i < nrows; i++)
		free(mat[i]);
	free(mat);
}

inline void BitMatrixMultiplication(uint8_t* resbuf, uint64_t resbytelen, uint8_t* invec, uint32_t inveclen,
		uint64_t** matrix, uint64_t* tmpbuf) {
	uint32_t columniters = ceil_divide(resbytelen, sizeof(uint64_t));
	uint32_t rowbit;
	memset((uint8_t*) tmpbuf, 0, columniters * sizeof(uint64_t));
	for(uint32_t i = 0, j; i < inveclen; i++) {
		rowbit = !!(invec[i>>3] & (0x01<<(i&0x07)));
		for(j = 0; j < columniters; j++) {
			tmpbuf[j] ^= (matrix[i][j] * rowbit);
			//cout << "rowbit = " << rowbit << ", matrix[i][j] = " << matrix[i][j] << ", tmpbuf = " << tmpbuf[j] << endl;
		}
	}
	memcpy(resbuf, tmpbuf, resbytelen);
	/*cout << (dec) << "out: " << resbytelen << ": "<<  (hex);
	for(uint32_t i = 0; i < resbytelen; i++) {
		cout << (uint32_t) resbuf[i];
	}
	cout << (dec) << endl;*/
}

#define OWF_BYTES AES_BYTES

inline void FixedKeyHashing(AES_KEY_CTX* aeskey, BYTE* outbuf, BYTE* inbuf, BYTE* tmpbuf, uint64_t id, uint32_t bytessecparam, crypto* crypt) {
	assert(bytessecparam <= AES_BYTES);
#ifdef HIGH_SPEED_ROT_LT
	((uint64_t*) tmpbuf)[0] = id ^ ((uint64_t*) inbuf)[0];
	((uint64_t*) tmpbuf)[1] = ((uint64_t*) inbuf)[1];
#else
	memset(tmpbuf, 0, AES_BYTES);
	memcpy(tmpbuf, (BYTE*) (&id), sizeof(uint64_t));

	for (uint32_t i = 0; i < bytessecparam; i++) {
		tmpbuf[i] = tmpbuf[i] ^ inbuf[i];
	}
#endif

	crypt->encrypt(aeskey, outbuf, tmpbuf, AES_BYTES);

#ifdef HIGH_SPEED_ROT_LT
	((uint64_t*) outbuf)[0] ^= ((uint64_t*) inbuf)[0];
	((uint64_t*) outbuf)[1] ^= ((uint64_t*) inbuf)[1];
#else
	for (uint32_t i = 0; i < bytessecparam; i++) {
		outbuf[i] = outbuf[i] ^ inbuf[i];
	}
#endif
}



#endif /* __OT_EXTENSION_H_ */

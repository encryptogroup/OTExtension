/*
 * alsz-ot-ext-snd.h
 *
 *  Created on: Mar 23, 2015
 *      Author: mzohner
 *
 * Malicious OT extension routine from ALSZ15
 */

#ifndef ALSZ_OT_EXT_SND_H_
#define ALSZ_OT_EXT_SND_H_

#include "ot-ext-snd.h"

typedef struct alsz_snd_check_ctx {
	uint64_t otid;
	uint64_t numblocks;
	linking_t* perm;
	uint8_t* seed_chk_buf;
	uint8_t* rcv_chk_buf;
} alsz_snd_check_t;



class ALSZOTExtSnd : public OTExtSnd {

public:
	ALSZOTExtSnd(uint32_t nSndVals, crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, uint32_t nbaseots,
			uint32_t nchecks, bool dobaseots=true) {
		InitSnd(nSndVals, crypt, rcvthread, sndthread, nbaseots);
		m_nChecks = nchecks;
		m_bDoBaseOTs = dobaseots;
	}
	;


	~ALSZOTExtSnd() {
	}
	;

	BOOL sender_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);


private:
	alsz_snd_check_t UpdateCheckBuf(uint8_t* tocheckseed, uint8_t* tocheckrcv, uint64_t otid, uint64_t numblocks, channel* check_chan);
	void XORandOWF(uint8_t* idaptr, uint8_t* idbptr, uint64_t rowbytelen, uint8_t* tmpbuf, uint8_t* resbuf, uint8_t* hash_buf);
	void genRandomPermutation(linking_t* outperm, uint32_t nids, uint32_t nperms);
	BOOL CheckConsistency(queue<alsz_snd_check_t>* check_buf_q, channel* check_chan);
	void FillAndSendRandomMatrix(uint64_t **rndmat, channel* chan);

	bool m_bDoBaseOTs;
};

#endif /* ALSZ_OT_EXT_SND_H_ */

/*
 * nnob-ot-ext-snd.h
 *
 *  Created on: Mar 23, 2015
 *      Author: mzohner
 *
 * Malicious OT extension routine from NNOB12
 */

#ifndef NNOB_OT_EXT_SND_H_
#define NNOB_OT_EXT_SND_H_

#include "ot-ext-snd.h"
#include "simpleot.h"

typedef struct nnob_snd_check_ctx {
	uint64_t otid;
	uint64_t numblocks;
	linking_t* perm;
	uint8_t* chk_buf;
	uint8_t* permchoicebits;
} nnob_snd_check_t;

class NNOBOTExtSnd : public OTExtSnd {

public:
	NNOBOTExtSnd( crypto* crypt, RcvThread* rcvthread, SndThread* sndthread, bool dobaseots=true) {
		uint32_t nbaseots = ceil_divide(crypt->get_seclvl().symbits * 8, 3);
		InitSnd(crypt, rcvthread, sndthread, nbaseots);
		m_nChecks = nbaseots / 2;
		m_bDoBaseOTs = dobaseots;
	}
	;


	~NNOBOTExtSnd() {
	}
	;

	BOOL sender_routine(uint32_t threadid, uint64_t numOTs);
	void ComputeBaseOTs(field_type ftype);


private:
	nnob_snd_check_t* UpdateCheckBuf(uint8_t* tocheckseed, uint8_t* tocheckrcv, uint64_t otid, uint64_t numblocks, channel* check_chan);
	void XORandOWF(uint8_t* idaptr, uint8_t* idbptr, uint64_t rowbytelen, uint8_t* tmpbuf, uint8_t* resbuf, uint8_t* hash_buf);
	void genRandomMapping(linking_t* outperm, uint32_t nids);
	BOOL CheckConsistency(queue<nnob_snd_check_t*>* check_buf_q, channel* check_chan);
	void FillAndSendRandomMatrix(uint64_t **rndmat, channel* chan);

	bool m_bDoBaseOTs;
};

#endif /* NNOB_OT_EXT_SND_H_ */

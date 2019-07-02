/**
 \file 		alsz-ot-ext-snd.cpp
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
 \brief
 */


#include <openssl/sha.h>
#include "alsz-ot-ext-snd.h"
#include "alsz-ot-ext-rec.h"
#include "simpleot.h"
#include "xormasking.h"
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/cbitvector.h>
#include <iostream>

BOOL ALSZOTExtSnd::sender_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;
	uint64_t processedOTBlocks = std::min(num_ot_blocks, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t tmpctr, tmpotlen;
	uint32_t nchans = 2;
	bool use_mat_chan = (m_eSndOTFlav == Snd_GC_OT || m_bUseMinEntCorRob);
	if(use_mat_chan) {
		nchans = 3;
	}

	channel* ot_chan = new channel(OT_BASE_CHANNEL+nchans*id, m_cRcvThread, m_cSndThread);
	channel* check_chan = new channel(OT_BASE_CHANNEL+nchans*id + 1, m_cRcvThread, m_cSndThread);
	channel* mat_chan;
	if(use_mat_chan) {
		mat_chan = new channel(nchans*id+2, m_cRcvThread, m_cSndThread);
	}

	uint64_t internal_numOTs = std::min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + internal_numOTs;
	uint64_t** rndmat;

	// The vector with the received bits
	CBitVector vRcv(m_nBaseOTs * OTsPerIteration);
	vRcv.Reset();

	// Holds the reply that is sent back to the receiver
	uint32_t numsndvals = 2;
	CBitVector* vSnd;

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration * m_cCrypt->get_aes_key_bytes() * 8);
#ifdef ZDEBUG
	std::cout << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << std::endl;
#endif
	vSnd = new CBitVector[numsndvals];
	for (uint32_t i = 0; i < numsndvals; i++) {
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Contains the parts of the V matrix
	CBitVector Q(wd_size_bits * OTsPerIteration);
	mask_buf_t tmpmaskbuf;

	uint64_t OT_ptr = myStartPos;

	uint8_t *rcvbuftmpptr, *rcvbufptr;

	std::queue<alsz_snd_check_t> check_queue;
	std::queue<mask_buf_t> mask_queue;

	OT_AES_KEY_CTX* tmp_base_keys;
	CBitVector* tmp_base_choices;

	uint64_t base_ot_block_ctr = OT_ptr / (myNumOTs);

	uint32_t startpos = 0;
	if(m_eRecOTFlav==Rec_R_OT) {
		startpos = 1;
	}

	if(m_eSndOTFlav == Snd_GC_OT) {
		initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
	}

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalUnMaskTime = 0,
			totalHashCheckTime = 0, totalChkCompTime = 0;
	timespec tempStart, tempEnd;
#endif

	while (OT_ptr < lim) //do while there are still transfers missing
	{
		processedOTBlocks = std::min(num_ot_blocks, ceil_divide(lim - OT_ptr, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;

#ifdef ZDEBUG
		std::cout << "Processing block " << nProgress << " with length: " << OTsPerIteration << ", and limit: " << lim << std::endl;
#endif

#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		rcvbufptr = ot_chan->blocking_receive_id_len(&rcvbuftmpptr, &tmpctr, &tmpotlen);
		//vRcv.AttachBuf(rcvbuftmpptr, bits_in_bytes(m_nBaseOTs * OTsPerIteration));
		vRcv.SetBytes(rcvbuftmpptr, bits_in_bytes(OTsPerIteration*startpos), bits_in_bytes((m_nBaseOTs-startpos)*OTsPerIteration));
		free(rcvbufptr);

		tmp_base_keys = m_tBaseOTKeys[base_ot_block_ctr];
		tmp_base_choices = m_tBaseOTChoices[base_ot_block_ctr];

		//m_tBaseOTQ.pop();
		//vRcv.PrintHex();
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalRcvTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		BuildQMatrix(&Q, OT_ptr, processedOTBlocks, tmp_base_keys);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalMtxTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		check_queue.push(UpdateCheckBuf(Q.GetArr(), vRcv.GetArr(), OT_ptr, processedOTBlocks, tmp_base_choices, check_chan));
		GenerateSendAndXORCorRobVector(&Q, OTsPerIteration, mat_chan);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalChkCompTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		FillAndSendRandomMatrix(rndmat, mat_chan);

		UnMaskBaseOTs(&Q, &vRcv, tmp_base_choices, processedOTBlocks);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalUnMaskTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		Q.Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalTnsTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		HashValues(&Q, seedbuf, vSnd, tmp_base_choices, OT_ptr, std::min(lim - OT_ptr, OTsPerIteration), rndmat);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalHshTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif

		//TODO: outsource into method
		tmpmaskbuf.otid = OT_ptr;
		tmpmaskbuf.otlen = std::min(lim - OT_ptr, OTsPerIteration);
		tmpmaskbuf.maskbuf = new CBitVector[numsndvals];
		for(uint32_t i = 0; i < numsndvals; i++)
			tmpmaskbuf.maskbuf[i].Copy(vSnd[i]);
		mask_queue.push(tmpmaskbuf);

		if(check_chan->data_available()) {
			assert(CheckConsistency(&check_queue, check_chan));
			//CheckConsistency(&check_queue, check_chan)
			tmpmaskbuf = mask_queue.front();
			mask_queue.pop();
			MaskAndSend(tmpmaskbuf.maskbuf, tmpmaskbuf.otid, tmpmaskbuf.otlen, ot_chan);
			delete[] tmpmaskbuf.maskbuf;
		}
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalHashCheckTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		OT_ptr += std::min(lim - OT_ptr, OTsPerIteration);
		base_ot_block_ctr++;

		//free(tmp_base_keys);
		//tmp_base_choices->delCBitVector();

		Q.Reset();
	}

	while(!check_queue.empty()) {
		if(check_chan->data_available()) {
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
			if(!CheckConsistency(&check_queue, check_chan)) {
				std::cerr << "OT extension consistency check failed. Aborting program\n";
				exit(0);
			}
			//assert(CheckConsistency(&check_queue, check_chan));
			//CheckConsistency(&check_queue, check_chan);
#ifdef OTTiming
			clock_gettime(CLOCK_MONOTONIC, &tempEnd);
			totalHashCheckTime += getMillies(tempStart, tempEnd);
			clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
			tmpmaskbuf = mask_queue.front();
			mask_queue.pop();
			MaskAndSend(tmpmaskbuf.maskbuf, tmpmaskbuf.otid, tmpmaskbuf.otlen, ot_chan);
#ifdef OTTiming
			clock_gettime(CLOCK_MONOTONIC, &tempEnd);
			totalSndTime += getMillies(tempStart, tempEnd);
#endif
		}
	}

	ot_chan->synchronize_end();
	check_chan->synchronize_end();


	vRcv.delCBitVector();
	Q.delCBitVector();
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].delCBitVector();
#ifndef ABY_OT
	delete[] seedbuf;
#endif

	for (uint32_t i = 0; i < numsndvals; i++)
		vSnd[i].delCBitVector();
#ifndef ABY_OT
	if (numsndvals > 0)
		delete[] vSnd;
#endif
	if(use_mat_chan) {
		mat_chan->synchronize_end();
	}

	if(m_eSndOTFlav == Snd_GC_OT) {
		freeRndMatrix(rndmat, m_nBaseOTs);
	}
#ifdef OTTiming
	std::cout << "Sender time benchmark for performing " << internal_numOTs << " OTs on " << m_nBitLength << " bit strings" << std::endl;
	std::cout << "Time needed for: " << std::endl;
	std::cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << std::endl;
	std::cout << "\t BaseOT Unmasking:\t" << totalUnMaskTime << " ms" << std::endl;
	std::cout << "\t Check Hashing: \t" << totalHashCheckTime << " ms" << std::endl;
	std::cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << std::endl;
	std::cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << std::endl;
	std::cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << std::endl;
	std::cout << "\t Checking Consistency:\t" << totalChkCompTime << " ms" << std::endl;
	std::cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << std::endl;
#endif


	delete ot_chan;
	delete check_chan;
	return TRUE;
}


void ALSZOTExtSnd::FillAndSendRandomMatrix(uint64_t **rndmat, channel* mat_chan) {
	if(m_eSndOTFlav == Snd_GC_OT) {
		uint8_t* rnd_seed = (uint8_t*) malloc(m_nSymSecParam);
		m_cCrypt->gen_rnd(rnd_seed, m_nSymSecParam);
		mat_chan->send(rnd_seed, m_nSymSecParam);
		fillRndMatrix(rnd_seed, rndmat, m_nBitLength, m_nBaseOTs, m_cCrypt);
		free(rnd_seed);
	}
}



alsz_snd_check_t ALSZOTExtSnd::UpdateCheckBuf(uint8_t* tocheckseed, uint8_t* tocheckrcv, uint64_t otid,
		uint64_t numblocks, CBitVector* choices, channel* check_chan) {
	uint64_t rowbytelen = m_nBlockSizeBytes * numblocks;
	uint8_t* hash_buf = (uint8_t*) malloc(SHA512_DIGEST_LENGTH);
	//uint8_t* tmpbuf = (uint8_t*) malloc(rowbytelen);
	uint8_t** tmpbuf = (uint8_t**) malloc(2 * sizeof(uint8_t*));
	alsz_snd_check_t check_buf;
	check_buf.rcv_chk_buf = (uint8_t*) malloc(m_nChecks * OWF_BYTES);
	check_buf.seed_chk_buf = (uint8_t*) malloc(m_nChecks * OWF_BYTES);
	uint8_t *seedcheckbufptr = check_buf.seed_chk_buf, *rcvcheckbufptr = check_buf.rcv_chk_buf;
	uint32_t iters = rowbytelen/sizeof(uint64_t);
	for(uint32_t i = 0; i < 2; i++) {
		tmpbuf[i] = (uint8_t*) malloc(rowbytelen);
	}
	check_buf.otid = otid;
	check_buf.numblocks = numblocks;
	check_buf.perm = (linking_t*) malloc(sizeof(linking_t*) * m_nChecks);
	check_buf.choices = choices;
	genRandomPermutation(check_buf.perm, m_nBaseOTs, m_nChecks);

	//right now the rowbytelen needs to be a multiple of AES_BYTES
	assert(ceil_divide(rowbytelen, OWF_BYTES) * OWF_BYTES == rowbytelen);
#ifdef DEBUG_ALSZ_CHECKS
	std::cout << "rowbytelen = " << rowbytelen << std::endl;
	choices->PrintHex();
#endif
	uint8_t *pas, *pbs, *par, *pbr;
	for(uint64_t i = 0; i < m_nChecks; i++, seedcheckbufptr+=OWF_BYTES, rcvcheckbufptr+=OWF_BYTES) {
		//memset(tmpbuf, 0, rowbytelen);
#ifdef DEBUG_ALSZ_CHECKS
		std::cout << i << "-th check between " << check_buf.perm[i].ida << " and " << check_buf.perm[i].idb << ": " << std::endl;
#endif
		pas = tocheckseed + check_buf.perm[i].ida * rowbytelen;
		pbs = tocheckseed + check_buf.perm[i].idb * rowbytelen;
		par = tocheckrcv + check_buf.perm[i].ida * rowbytelen;
		pbr = tocheckrcv + check_buf.perm[i].idb * rowbytelen;
		for(uint64_t j = 0; j < iters; j++) {
			((uint64_t*) tmpbuf[0])[j] = ((uint64_t*) pas)[j] ^ ((uint64_t*) pbs)[j];
			((uint64_t*) tmpbuf[1])[j] = ((uint64_t*) tmpbuf[0])[j] ^ ((uint64_t*) par)[j] ^ ((uint64_t*) pbr)[j];
		}
		sha512_hash(seedcheckbufptr, OWF_BYTES, tmpbuf[0], rowbytelen, hash_buf);
		sha512_hash(rcvcheckbufptr, OWF_BYTES, tmpbuf[1], rowbytelen, hash_buf);
		/*XORandOWF(tocheckseed + check_buf.perm[i].ida * rowbytelen, tocheckseed + check_buf.perm[i].idb * rowbytelen,
				rowbytelen, tmpbuf, seedcheckbufptr, hash_buf);
		XORandOWF(tocheckrcv + check_buf.perm[i].ida * rowbytelen, tocheckrcv + check_buf.perm[i].idb * rowbytelen,
				rowbytelen, tmpbuf, rcvcheckbufptr, hash_buf);*/
	}

	for(uint32_t i = 0; i < 2; i++)
		free(tmpbuf[i]);
	free(tmpbuf);
	//free(tmpbuf);
	free(hash_buf);

	//Send the permutation over to the receiver
	check_chan->send_id_len((uint8_t*) check_buf.perm, sizeof(linking_t) * m_nChecks, otid, numblocks);

	return check_buf;
}

void ALSZOTExtSnd::XORandOWF(uint8_t* idaptr, uint8_t* idbptr, uint64_t rowbytelen, uint8_t* tmpbuf,
		uint8_t* resbuf, uint8_t* hash_buf) {

	for(uint64_t j = 0; j < rowbytelen/sizeof(uint64_t); j++) {
		((uint64_t*) tmpbuf)[j] = ((uint64_t*) tmpbuf)[j] ^ ((uint64_t*) idaptr)[j] ^ ((uint64_t*) idbptr)[j];
	}

#ifdef DEBUG_ALSZ_CHECKS_INPUT
		std::cout << "\t" << (std::hex);
		for(uint32_t t = 0; t < rowbytelen; t++) {
			std::cout << std::setw(2) << std::setfill('0') << (uint32_t) tmpbuf[t];
		}
		std::cout << (std::dec) << std::endl;
#endif
#ifdef AES_OWF
		owf(&aesowfkey, rowbytelen, tmpbuf, resbuf);
#else
	/*SHA512_CTX sha;
	SHA512_Init(&sha);
	SHA512_Update(&sha, tmpbuf, rowbytelen);
	SHA512_Final(hash_buf, &sha);
	memcpy(resbuf, hash_buf, OWF_BYTES);*/
	sha512_hash(resbuf, OWF_BYTES, tmpbuf, rowbytelen, hash_buf);
	//m_cCrypt->hash_buf(resbuf, OWF_BYTES, tmpbuf, rowbytelen, hash_buf);//hash_buf, rowbytelen, tmpbuf, resbuf, hash_buf);
#endif
#ifdef DEBUG_ALSZ_CHECKS_OUTPUT
		std::cout << "\t" << (std::hex);
		for(uint32_t t = 0; t < OWF_BYTES; t++) {
			std::cout << (uint32_t) resbuf[t];
		}
		std::cout << (std::dec) << std::endl;
#endif
}

BOOL ALSZOTExtSnd::CheckConsistency(std::queue<alsz_snd_check_t>* check_buf_q, channel* check_chan) {
	uint8_t *rcvhashbufptr, *seedbufsrvptr, *rcvbufsrvptr, *rcvhashbuf;
	uint32_t ida, idb, receiver_hashes = 4;
	uint64_t checkbytelen= receiver_hashes * OWF_BYTES, tmpid, tmpnblocks, seedhashcli, rcvhashcli;

	uint8_t* rcvbuf = check_chan->blocking_receive_id_len(&rcvhashbuf, &tmpid, &tmpnblocks);
	uint8_t ca, cb;

	alsz_snd_check_t check_buf = check_buf_q->front();
	check_buf_q->pop();

	//Should be fine since the blocks are handled sequentially - but recheck anyway
	assert(check_buf.otid == tmpid);
	assert(check_buf.numblocks == tmpnblocks);

	// uint32_t blockoffset = ceil_divide(check_buf.otid, num_ot_blocks * m_nBlockSizeBytes);
	uint32_t offset = 0 ;//m_nBaseOTs * blockoffset;//TODO, put offset in again when 3-stop ot is implemented

	rcvhashbufptr = rcvhashbuf;

	seedbufsrvptr = check_buf.seed_chk_buf;
	rcvbufsrvptr = check_buf.rcv_chk_buf;

	for(uint32_t i = 0, j; i < m_nChecks; i++, rcvhashbufptr+=checkbytelen) {
		ida = check_buf.perm[i].ida;
		idb = check_buf.perm[i].idb;
		assert(ida < m_nBaseOTs && idb < m_nBaseOTs);

		//ca = m_vU.GetBit(ida + offset);
		//cb = m_vU.GetBit(idb + offset);
		ca = check_buf.choices->GetBit(ida + offset);
		cb = check_buf.choices->GetBit(idb + offset);

		//check that ida+idb == seedbufcheck and (!ida) + (!idb) == rcvbufcheck
		for(j = 0; j < ceil_divide(OWF_BYTES,sizeof(uint64_t)); j++, seedbufsrvptr+=sizeof(uint64_t), rcvbufsrvptr+=sizeof(uint64_t)) {

			seedhashcli = *(((uint64_t*) rcvhashbufptr) + (2*ca+cb)*2 + j);
			rcvhashcli = *(((uint64_t*) rcvhashbufptr) + (2*(ca^1)+(cb^1))*2 + j);


			if(seedhashcli != *((uint64_t*) seedbufsrvptr) || rcvhashcli != *((uint64_t*) rcvbufsrvptr)) {
#ifdef DEBUG_ALSZ_CHECKS
				std::cout << "Error in " << i <<"-th consistency check between " << ida << " and " << idb <<" : " << std::endl;
				std::cout << "Receiver seed = " << (std::hex) << ((uint64_t*) (rcvhashbufptr+((2*ca+cb) * OWF_BYTES)))[0] <<
						((uint64_t*) (rcvhashbufptr+((2*ca+cb) * OWF_BYTES) + j))[1] << ", my seed: " <<
						((uint64_t*) seedbufsrvptr)[0] << ((uint64_t*) seedbufsrvptr)[1] << (std::dec) << std::endl;
				std::cout << "Receiver sndval = " << (std::hex) << ((uint64_t*) (rcvhashbufptr+((2*(ca^1)+(cb^1)) * OWF_BYTES) + j))[0] <<
						((uint64_t*) (rcvhashbufptr+((2*(ca^1)+(cb^1)) * OWF_BYTES) + j))[1] << ", my snd val = " <<
						((uint64_t*) rcvbufsrvptr)[0] << ((uint64_t*) rcvbufsrvptr)[1] << (std::dec) << std::endl;
#endif
				return false;
			}
		}
	}
	//free the receive buffer
	free(rcvbuf);
	free(check_buf.perm);
	free(check_buf.rcv_chk_buf);
	free(check_buf.seed_chk_buf);
	// do not delete(check_buf.choices): all choices vectors are freed in ~OTExtSnd()

	return TRUE;
}


void ALSZOTExtSnd::genRandomPermutation(linking_t* outperm, uint32_t nids, uint32_t nperms) {
	uint64_t bitsint = (8 * sizeof(uint32_t));
	uint32_t rnditers = ceil_divide(m_cCrypt->get_seclvl().symbits, bitsint);
	CBitVector rndstring;
	rndstring.Create((uint64_t) rnditers * nperms, bitsint, m_cCrypt);

	// uint64_t tmpval = 0, tmprnd;
	// uint32_t rndctr=0;

	for(uint32_t i = 0; i < nperms; i++) {
		outperm[i].ida = i % nids;
		//if(outperm[i].ida == 0) outperm[i].ida++;
		/*for(uint32_t j = 0; j < rnditers; j++, rndctr++) {
			tmprnd = rndstring.Get<uint32_t>(rndctr);
			tmpval = ((uint64_t) (tmpval << bitsint) | tmprnd);
			tmpval = tmpval % nids;
		}*/
		m_cCrypt->gen_rnd_uniform(&outperm[i].idb, nids);
		//outperm[i].idb = 0;
		//if(outperm[i].idb == 0) outperm[i].idb++;
		//std::cout << "Permutation " << i << ": " << outperm[i].ida << " <-> " << outperm[i].idb << std::endl;
	}

	rndstring.delCBitVector();
}

//Do a 3-step OT extension
void ALSZOTExtSnd::ComputeBaseOTs(field_type ftype) {
	if(m_bDoBaseOTs) { //use public-key crypto routines (simple OT)
		m_cBaseOT = new SimpleOT(m_cCrypt, ftype);
		ComputePKBaseOTs();
		delete m_cBaseOT;

		/*CBitVector* tmp_choices = new CBitVector();
		tmp_choices->Create(m_nBaseOTs);
		for (uint32_t i = 0; i < PadToMultiple(m_nBaseOTs, 8); i++)
			tmp_choices->SetBit(i, m_vU.GetBit(i));

		//tmp->choices->SetBits(m_vU.GetArr(), (uint64_t) 0, m_nBaseOTs);
		tmp->base_ot_key_ptr = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nBaseOTs );
		memcpy(tmp->base_ot_key_ptr, m_vBaseOTKeys, sizeof(AES_KEY_CTX) * m_nBaseOTs);
		m_tBaseOTQ.push_back(tmp);*/
	} else {
		ALSZOTExtRec* rec = new ALSZOTExtRec(m_cCrypt, m_cRcvThread, m_cSndThread, m_nBaseOTs, m_nChecks);
		uint32_t numots = buffer_ot_keys * m_nBaseOTs;
		XORMasking* m_fMaskFct = new XORMasking(m_cCrypt->get_seclvl().symbits);
		CBitVector U, resp;
		uint32_t secparambytes = bits_in_bytes(m_cCrypt->get_seclvl().symbits);
		uint32_t nsndvals = 2;

		U.Create(numots, m_cCrypt);
		resp.Create(m_cCrypt->get_seclvl().symbits * numots);

		rec->computePKBaseOTs();
		rec->ComputeBaseOTs(ftype);

		rec->receive(numots, m_cCrypt->get_seclvl().symbits, nsndvals, &U, &resp, Snd_R_OT, Rec_R_OT, 1, m_fMaskFct);

		CBitVector* tmp_choices;
		OT_AES_KEY_CTX* tmp_keys;
		//assign keys to base OT queue
		for(uint32_t i = 0; i < buffer_ot_keys; i++) {
			tmp_choices = new CBitVector();
			tmp_choices->Create(m_nBaseOTs);
			for (uint32_t j = 0; j < m_nBaseOTs; j++)
				tmp_choices->SetBit(j, U.GetBitNoMask(i * m_nBaseOTs + j));
			m_tBaseOTChoices.push_back(tmp_choices);

			//tmp->choices->SetBits(U.GetArr(), (uint64_t) i * m_nBaseOTs, (uint64_t) m_nBaseOTs);
			tmp_keys = (OT_AES_KEY_CTX*) malloc(sizeof(OT_AES_KEY_CTX) * m_nBaseOTs);

			InitAESKey(tmp_keys, resp.GetArr()+i*m_nBaseOTs*secparambytes, m_nBaseOTs, m_cCrypt);
			m_tBaseOTKeys.push_back(tmp_keys);

		}

		U.delCBitVector();
		resp.delCBitVector();
		delete m_fMaskFct;
		delete rec;
	}


	//if(m_tBaseOTQ.size() == 0) {


	/*base_ots_t* baseOTs = (base_ots_t*) malloc(sizeof(base_ots_t));
	baseOTs->base_ot_key_ptr = m_vBaseOTKeys;
	//m_tBaseOTQ.push(baseOTs);
	//}

	//Extend OTs further and pack into m_tBaseOTQ
	uint32_t numkeys = buffer_ot_keys;
	base_ots_t** extended_keys;// = (base_ots_t**) malloc(sizeof(base_ots_t*) * numkeys);
	for(uint32_t i = 0; i < numkeys; i++) {
		keys[i] = m_tBaseOTQ.front();
		m_tBaseOTQ.pop();
	}
	uint32_t numkeys = rec->ExtendBaseKeys(0, 0, &extended_keys)
	//uint32_t nkeys = ExtendBaseKeys(0, 0, &keys);
	for(uint32_t i = 0; i < nkeys; i++) {
		m_tBaseOTQ.push(keys[i]);
	}
	if(nkeys > 0)
		free(keys);*/

}

/*uint32_t ALSZOTExtSnd::ExtendBaseKeys(uint32_t id, uint64_t nbasekeys, base_ots_t*** out_keys) {
	assert(m_tBaseOTQ.size() > 0);
	//+1 to have some offset for future OTs
	uint32_t req_key_sets = ceil_divide(nbasekeys, num_ot_blocks) + buffer_ot_keys;
	if(req_key_sets > m_tBaseOTQ.size()*num_ot_blocks) {
		uint32_t numkeys = req_key_sets - m_tBaseOTQ.size();
		base_ots_t** keys = (base_ots_t**) malloc(sizeof(base_ots_t*) * numkeys);
		for(uint32_t i = 0; i < numkeys; i++) {
			keys[i] = m_tBaseOTQ.front();
			m_tBaseOTQ.pop();
		}
		OTExtRec* rec = new ALSZOTExtRec(m_nSndVals, m_cCrypt, m_cRcvThread, m_cSndThread, m_nBaseOTs, m_nChecks, keys);
		rec->ExtendBaseKeys(id, req_key_sets, out_keys);
		//TODO Assign keys
		//InitPRFKeys(keyBuf, m_nBaseOTs);
		return req_key_sets;
	} else {
		//else do nothing since sufficient keys are left
		return 0;
	}
}*/

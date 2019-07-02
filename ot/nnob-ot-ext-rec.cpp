/**
 \file 		nnob-ot-ext-rec.cpp
 \author	
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
            along with this program. If not, see <http://www.gnu.org/licenses/>._______________
 \brief
 */


#include <openssl/sha.h>
#include "nnob-ot-ext-rec.h"
#include "simpleot.h"
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/cbitvector.h>


BOOL NNOBOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;

	myNumOTs = std::min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + myNumOTs;

	uint64_t processedOTBlocks = std::min(num_ot_blocks, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t OTwindow = num_ot_blocks * wd_size_bits;
	uint64_t** rndmat;
	bool use_mat_chan = (m_eSndOTFlav == Snd_GC_OT || m_bUseMinEntCorRob);
	uint32_t nchans = 2;
	if(use_mat_chan) {
		nchans = 3;
	}

	channel* ot_chan = new channel(OT_BASE_CHANNEL+nchans*id, m_cRcvThread, m_cSndThread);
	channel* check_chan = new channel(OT_BASE_CHANNEL+nchans*id+1, m_cRcvThread, m_cSndThread);
	channel* mat_chan;
	if(use_mat_chan) {
		mat_chan = new channel(nchans*id+2, m_cRcvThread, m_cSndThread);
	}

	// A temporary part of the T matrix
	CBitVector T(wd_size_bits * OTsPerIteration);

	// The send buffer
	CBitVector vSnd(m_nBaseOTs * OTsPerIteration);

	// A temporary buffer that stores the resulting seeds from the hash buffer
	//TODO: Check for some maximum size
	CBitVector seedbuf(OTwindow * m_cCrypt->get_aes_key_bytes() * 8);

	uint64_t otid = myStartPos;
	std::queue<nnob_rcv_check_t> check_buf;

	std::queue<mask_block*> mask_queue;
	CBitVector maskbuf;
	maskbuf.Create(m_nBitLength * OTwindow);

	//TODO only do when successfull checks
	if(m_eSndOTFlav == Snd_GC_OT) {
		initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
	}

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0,
			totalChkTime = 0, totalMaskTime = 0, totalEnqueueTime = 0;
	timespec tempStart, tempEnd;
#endif

	while (otid < lim) {
		processedOTBlocks = std::min(num_ot_blocks, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		//nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		BuildMatrices(&T, &vSnd, otid, processedOTBlocks, m_tBaseOTKeys.front());
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalMtxTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		check_buf.push(EnqueueSeed(T.GetArr(), otid, processedOTBlocks));
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalEnqueueTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		MaskBaseOTs(&T, &vSnd, otid, processedOTBlocks);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalMaskTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		SendMasks(&vSnd, ot_chan, otid, OTsPerIteration);
		//ot_chan->send_id_len(vSnd.GetArr(), nSize, otid, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalSndTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		ReceiveAndFillMatrix(rndmat, mat_chan);
		ReceiveAndXORCorRobVector(&T, OTsPerIteration, mat_chan);

		T.Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalTnsTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif

		HashValues(&T, &seedbuf, &maskbuf, otid, std::min(lim - otid, OTsPerIteration), rndmat);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalHshTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		if(check_chan->data_available()) {
			ComputeOWF(&check_buf, check_chan);
		}
		//if(ot_chan->data_available()) {
		//	ReceiveAndUnMask(ot_chan);
		//}
		SetOutput(&maskbuf, otid, OTsPerIteration, &mask_queue, ot_chan);

		otid += std::min(lim - otid, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalRcvTime += getMillies(tempStart, tempEnd);
#endif

		vSnd.Reset();
		T.Reset();
	}

	while(!check_buf.empty()) {
		if(check_chan->data_available()) {
			ComputeOWF(&check_buf, check_chan);
		}
	}


	if(m_eSndOTFlav != Snd_R_OT) {
		//finevent->Wait();
#ifdef ABY_OT
		while(!(mask_queue.empty())) {
#else
		while(ot_chan->is_alive() && !(mask_queue.empty())) {
#endif
			ReceiveAndUnMask(ot_chan, &mask_queue);
		}
	}
	ot_chan->synchronize_end();
	check_chan->synchronize_end();
	delete ot_chan;
	delete check_chan;

	T.delCBitVector();
	vSnd.delCBitVector();
	seedbuf.delCBitVector();
	maskbuf.delCBitVector();

	if(use_mat_chan) {
		mat_chan->synchronize_end();
		delete mat_chan;
	}

	if(m_eSndOTFlav==Snd_GC_OT) {
		freeRndMatrix(rndmat, m_nBaseOTs);
	}

#ifdef OTTiming
	std::cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << std::endl;
	std::cout << "Time needed for: " << std::endl;
	std::cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << std::endl;
	std::cout << "\t Enqueuing Seeds:\t" << totalEnqueueTime << " ms" << std::endl;
	std::cout << "\t Base OT Masking:\t" << totalMaskTime << " ms" << std::endl;
	std::cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << std::endl;
	std::cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << std::endl;
	std::cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << std::endl;
	std::cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << std::endl;
#endif


	return TRUE;
}


void NNOBOTExtRec::ReceiveAndFillMatrix(uint64_t** rndmat, channel* mat_chan) {
	if(m_eSndOTFlav == Snd_GC_OT) {
		uint8_t* rnd_seed = mat_chan->blocking_receive();
		//initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
		fillRndMatrix(rnd_seed, rndmat, m_nBitLength, m_nBaseOTs, m_cCrypt);
		free(rnd_seed);
	}
}

nnob_rcv_check_t NNOBOTExtRec::EnqueueSeed(uint8_t* T0, uint64_t otid, uint64_t numblocks) {
	uint64_t expseedbytelen = m_nBaseOTs * numblocks * m_nBlockSizeBytes;
	nnob_rcv_check_t seedstr;

	seedstr.otid = otid;
	seedstr.numblocks = numblocks;
	seedstr.T0 = (uint8_t*) malloc(expseedbytelen);

	memcpy(seedstr.T0, T0, expseedbytelen);

	return seedstr;
}



void NNOBOTExtRec::ComputeOWF(std::queue<nnob_rcv_check_t>* check_buf_q, channel* check_chan) {//linking_t* permbits, int nchecks, int otid, int processedOTs, BYTE* outhashes) {

	//Obtain T0 and T1 from the SeedPointers
	uint32_t receiver_hashes = 1;

	uint64_t tmpid, tmpnblocks;
	linking_t* perm;
	uint8_t* rcv_buf_perm = check_chan->blocking_receive_id_len((uint8_t**) &perm, &tmpid, &tmpnblocks);
	uint8_t* rcv_buf_permchoices = check_chan->blocking_receive();
	uint8_t* sender_permchoicebitptr = rcv_buf_permchoices;

	nnob_rcv_check_t check_buf = check_buf_q->front();

	check_buf_q->pop();

	assert(tmpid == check_buf.otid);
	assert(tmpnblocks == check_buf.numblocks);

	//the bufsize has to be padded to a multiple of the PRF-size since we will omit boundary checks there
	uint32_t i, j;
	uint64_t bufrowbytelen = m_nBlockSizeBytes * check_buf.numblocks;//seedptr->expstrbitlen>>3;//(CEIL_DIVIDE(processedOTs, wd_size_bits) * wd_size_bits) >>3;
	uint64_t checkbytelen = std::min(bufrowbytelen, bits_in_bytes(m_nOTs - check_buf.otid));
	//contains the T-matrix
	uint8_t* T0 = check_buf.T0;
	//contains the T-matrix XOR the receive bits
	//uint8_t* T1 = check_buf.T1;

	uint32_t outhashbytelen = m_nChecks * OWF_BYTES * receiver_hashes;
	uint8_t* outhashes = (uint8_t*) malloc(outhashbytelen);

#ifdef AES_OWF
	AES_KEY_CTX aesowfkey;
	MPC_AES_KEY_INIT(&aesowfkey);
#else
	uint8_t* hash_buf = (uint8_t*) malloc(SHA512_DIGEST_LENGTH);
#endif
	uint8_t* tmpbuf = (uint8_t*) malloc(bufrowbytelen);
	uint8_t **ka = (uint8_t**) malloc(2 * sizeof(uint8_t*));
	uint8_t **kb = (uint8_t**) malloc(2 * sizeof(uint8_t*));
	uint8_t  *kaptr, *kbptr;
	uint8_t* outptr = outhashes;

	uint8_t* receiver_choicebits = m_vChoices->GetArr() + ceil_divide(check_buf.otid, 8);
	CBitVector tmp;
	tmp.AttachBuf(tmpbuf, bufrowbytelen*8);

	//Compute all hashes for the permutations given Ta, Tb and the choice bits
	for(i = 0; i < m_nChecks; i++, sender_permchoicebitptr++) {
		ka[0] = T0 + perm[i].ida * bufrowbytelen;
		kb[0] = T0 + perm[i].idb * bufrowbytelen;

	#ifdef DEBUG_MALICIOUS
		std::cout << (std::dec) << i << "-th check: between " << perm[i].ida << ", and " << perm[i].idb << std::endl;
	#endif
		for(j = 0; j < receiver_hashes; j++, outptr+=OWF_BYTES) {
			kaptr = ka[0];
			kbptr = kb[0];

			assert((*sender_permchoicebitptr) == 0 || (*sender_permchoicebitptr == 1));

			tmp.SetXOR(kaptr, kbptr, 0, bufrowbytelen);
			if(*sender_permchoicebitptr == 1) {
				tmp.XORBytesReverse(receiver_choicebits, 0, checkbytelen);
			}

#ifdef DEBUG_NNOB_CHECKS_INPUT
			std::cout << "XOR-OWF Input:\t" << (std::hex);
			for(uint32_t t = 0; t < checkbytelen; t++) {
				std::cout << std::setw(2) << std::setfill('0') << (uint32_t) tmpbuf[t];
			}
			std::cout << (std::dec) << std::endl;
#endif
	#ifdef AES_OWF
			owf(&aesowfkey, rowbytelen, tmpbuf, outhashes);
	#else
			//m_cCrypt->hash_buf(outptr, OWF_BYTES, tmpbuf, checkbytelen, hash_buf);
			sha512_hash(outptr, OWF_BYTES, tmpbuf, checkbytelen, hash_buf);
	#endif
#ifdef DEBUG_NNOB_CHECKS_OUTPUT
			std::cout << "XOR-OWF Output:\t" << (std::hex);
			for(uint32_t t = 0; t < OWF_BYTES; t++) {
				std::cout << (uint32_t) outptr[t];
			}
			std::cout << (std::dec) << std::endl;
#endif
		}
	}
	check_chan->send_id_len(outhashes, outhashbytelen, check_buf.otid, check_buf.numblocks);

	free(rcv_buf_perm);
	free(rcv_buf_permchoices);
	//free(tmpbuf);
	free(ka);
	free(kb);
	free(check_buf.T0);
	//free(check_buf.T1);
	free(outhashes);
#ifndef AES_OWF
	free(hash_buf);
#endif
}

void NNOBOTExtRec::ComputeBaseOTs(field_type ftype) {
	if(m_bDoBaseOTs) {
		m_cBaseOT = new SimpleOT(m_cCrypt, ftype);
		ComputePKBaseOTs();
		delete m_cBaseOT;
	} else {
		//recursive call
	}
}

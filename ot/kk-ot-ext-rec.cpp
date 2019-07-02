/**
 \file 		kk-ot-ext-rec.cpp
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

#include "kk-ot-ext-rec.h"
#include "naor-pinkas.h"
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/cbitvector.h>
#include <iostream>


BOOL KKOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	assert(m_eSndOTFlav != Snd_GC_OT); //not working for GC_OT
	assert(m_nSndVals <= m_nBaseOTs);

	set_internal_sndvals(m_nSndVals, m_nBitLength);

	//uint32_t choicecodebitlen = ceil_log2(m_nint_sndvals);
	uint32_t int_choicecodebits = ceil_log2(m_nint_sndvals);
	uint32_t ext_choicecodebits = ceil_log2(m_nSndVals);
	uint32_t diff_choicecodes = int_choicecodebits / ext_choicecodebits;

	uint64_t myStartPos = id * myNumOTs;
	uint64_t myStartPos1ooN = ceil_divide(myStartPos, diff_choicecodes);
	uint64_t wd_size_bits = m_nBlockSizeBits;

	myNumOTs = std::min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	//TODO some re-formating of myNumOTs due to 1ooN OT
	uint64_t lim = myStartPos1ooN + ceil_divide(myNumOTs, diff_choicecodes);

	if(myStartPos1ooN * diff_choicecodes > m_nOTs) {
		std::cerr << "Thread " << id << " not doing any work to align to window size " << std::endl;
		return true;
	}


	uint64_t processedOTBlocks = std::min(num_ot_blocks, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t OTwindow = num_ot_blocks * wd_size_bits;
	uint64_t** rndmat;
	uint64_t processedOTs;
	channel* chan = new channel(OT_BASE_CHANNEL+id, m_cRcvThread, m_cSndThread);

	// A temporary part of the T matrix
	CBitVector T(wd_size_bits * OTsPerIteration);

	// The send buffer
#ifdef GENERATE_T_EXPLICITELY
	CBitVector vSnd(m_nBaseOTs * OTsPerIteration * 2);
#else
	CBitVector vSnd(m_nBaseOTs * OTsPerIteration);
#endif

	// A temporary buffer that stores the resulting seeds from the hash buffer
	//TODO: Check for some maximum size
	CBitVector seedbuf(OTwindow * m_cCrypt->get_aes_key_bytes() * 8);

	uint64_t otid = myStartPos1ooN;

	std::queue<mask_block*> mask_queue;

	CBitVector maskbuf;
	maskbuf.Create(m_nBitLength * OTwindow * diff_choicecodes);

	//Choice bits corresponding to the codeword
	CBitVector choicecodes(m_nCodeWordBits * m_nCodeWordBits);
	choicecodes.Reset();

	if(m_eSndOTFlav == Snd_GC_OT) {
		uint8_t* rnd_seed = chan->blocking_receive();
		initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
		fillRndMatrix(rnd_seed, rndmat, m_nBitLength, m_nBaseOTs, m_cCrypt);
		free(rnd_seed);
	}

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0,
			totalChkTime = 0, totalMaskTime = 0, totalChoiceTime = 0;
	timespec tempStart, tempEnd;
#endif

	while (otid < lim) {
		processedOTBlocks = std::min(num_ot_blocks, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		processedOTs = std::min(lim - otid, OTsPerIteration);
		//nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		BuildMatrices(&T, &vSnd, otid, processedOTBlocks, m_tBaseOTKeys.front());

#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalChoiceTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		//generate the code elements that correspond to my choice bits
		GenerateChoiceCodes(&choicecodes, &vSnd, &T, otid, processedOTs);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalMtxTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		//MaskBaseOTs(T, vSnd, otid, processedOTBlocks);
		KKMaskBaseOTs(&T, &vSnd, processedOTBlocks);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalMaskTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		T.Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalTnsTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		KKHashValues(&T, &seedbuf, &maskbuf, otid, processedOTs, rndmat);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalHshTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		SendMasks(&vSnd, chan, otid, OTsPerIteration, 0);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalSndTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		//SetOutput(maskbuf, otid, OTsPerIteration, &mask_queue, chan);//ReceiveAndUnMask(chan);
		KKSetOutput(&maskbuf, otid, processedOTs, &mask_queue, chan);
		//counter += std::min(lim - OT_ptr, OTsPerIteration);
		otid += std::min(lim - otid, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalRcvTime += getMillies(tempStart, tempEnd);
#endif

		vSnd.Reset();
		T.Reset();
	}
	//sndthread->signal_end(id);
#ifdef ABY_OT
	while(!(mask_queue.empty())) {
#else
	while(chan->is_alive() && !(mask_queue.empty())) {
#endif
		KKReceiveAndUnMask(chan, &mask_queue);
	}

	chan->synchronize_end();
	delete chan;

	/*T.delCBitVector();
	vSnd.delCBitVector();
	seedbuf.delCBitVector();
	maskbuf.delCBitVector();*/
	if(m_eSndOTFlav==Snd_GC_OT)
		freeRndMatrix(rndmat, m_nBaseOTs);
#ifdef OTTiming
	std::cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << std::endl;
	std::cout << "Time needed for: " << std::endl;
	std::cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << std::endl;
	std::cout << "\t Base OT Masking:\t" << totalMaskTime << " ms" << std::endl;
	std::cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << std::endl;
	std::cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << std::endl;
	std::cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << std::endl;
	std::cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << std::endl;
#endif

	return TRUE;
}


void KKOTExtRec::GenerateChoiceCodes(CBitVector* choicecodes, CBitVector* vSnd, CBitVector* T, uint32_t startpos, uint32_t len) {
	uint32_t tmpchoice;
	uint32_t otid = startpos;
	uint32_t ncolumnsbyte = ceil_divide(len, m_nCodeWordBits) * m_nCodeWordBytes;
	uint32_t choicecodebitlen = ceil_log2(m_nint_sndvals);

	//std::cout << "vSnd In: ";
	//vSnd.PrintHex(0, ncolumnsbyte*len);
	//Generate choice bits as XOR of vSnd and T
	if(m_eRecOTFlav == Rec_R_OT) {
		CBitVector tmp;
		uint32_t bufbits = ncolumnsbyte * 8 * choicecodebitlen;
		tmp.Create(bufbits);
		tmp.Reset();
		tmp.XORBytesReverse(vSnd->GetArr(), 0, bits_in_bytes(bufbits));
		tmp.XORBytesReverse(T->GetArr(), 0, bits_in_bytes(bufbits));

		//tmp.XORBytes(vSnd.GetArr(), 0, bits_in_bytes(bufbits));
		//tmp.XORBytes(T.GetArr(), 0, bits_in_bytes(bufbits));
		for(uint32_t i = 0; i < len; i++) {
			for(uint32_t j = 0; j < choicecodebitlen; j++) {
				m_vChoices->SetBit(j+(otid+i)*choicecodebitlen, tmp.GetBit(j * ncolumnsbyte*8+i));
			}
		}

		//m_vChoices->Copy(tmp.GetArr(), ceil_divide(startpos*choicecodebitlen, 8), len * m_nCodeWordBits);
		//tmp.delCBitVector();
	}

	for(uint32_t pos = 0; pos < len; pos+=m_nCodeWordBits) {

		//build blocks of 256x256 code bits
		choicecodes->Reset();
		for(uint32_t j = 0; j < std::min(len - pos, m_nCodeWordBits); j++, otid++) {
			tmpchoice = m_vChoices->Get<uint32_t>(otid * choicecodebitlen, choicecodebitlen);
			//std::cout << "otid = " << otid << ", choice = " << tmpchoice << std::endl;
			choicecodes->SetBytes((uint8_t*) m_vCodeWords[tmpchoice], j*m_nCodeWordBytes, m_nCodeWordBytes);
		}
		//std::cout << "Using codeword " << (std::hex) << m_vCodeWords[tmpchoice][0] << m_vCodeWords[tmpchoice][1] << (std::hex) <<
		//		m_vCodeWords[tmpchoice][2] << m_vCodeWords[tmpchoice][3] << (std::dec) << std::endl;

		//transpose these 256x256 code bits to match the order of the T matrix
		choicecodes->EklundhBitTranspose(m_nCodeWordBits, m_nCodeWordBits);

		//XOR these transposed choice bits blockwise on the matrix that is sent to S
		for(uint32_t j = 0; j < m_nCodeWordBits; j++) {
			vSnd->XORBytes(choicecodes->GetArr() + j * m_nCodeWordBytes, (pos >> 3) + j * ncolumnsbyte, m_nCodeWordBytes);
		}
	}
	//std::cout << "vSnd Out: ";
	//vSnd.PrintHex(0, ncolumnsbyte*len);
}

void KKOTExtRec::KKHashValues(CBitVector* T, CBitVector* seedbuf, CBitVector* maskbuf, uint64_t OT_ptr, uint64_t OT_len, uint64_t** mat_mul) {
	//uint32_t wd_size_bytes = m_nBlockSizeBytes;//(1 << ((ceil_log2(m_nBaseOTs)) - 3));
	uint32_t rowbytelen = bits_in_bytes(m_nBaseOTs);
	uint32_t hashinbytelen = rowbytelen + sizeof(uint64_t);
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	uint8_t* Tptr = T->GetArr();
	uint8_t* bufptr = seedbuf->GetArr();

	uint8_t* inbuf = (uint8_t*) calloc(hashinbytelen, 1);
	uint8_t* resbuf = (uint8_t*) calloc(m_cCrypt->get_hash_bytes(), 1);
	uint8_t* hash_buf = (uint8_t*) calloc(m_cCrypt->get_hash_bytes(), 1);

	uint64_t* tmpbuf = (uint64_t*) calloc(PadToMultiple(bits_in_bytes(m_nBitLength), sizeof(uint64_t)), 1);
	uint8_t* tmpbufb = (uint8_t*) calloc(bits_in_bytes(m_nBitLength), 1);

	uint32_t int_choicecodebits = ceil_log2(m_nint_sndvals);
	uint32_t ext_choicecodebits = ceil_log2(m_nSndVals);
	uint32_t diff_choicecodes = int_choicecodebits / ext_choicecodebits;

#ifdef USE_PIPELINED_AES_NI
	AES_KEY tk_aeskey;
	block inblock, outblock;
	tk_aeskey.rounds = 14;

	uint64_t* global_OT_ptr = (uint64_t*) inbuf;
	*global_OT_ptr = OT_ptr + m_nCounter;
#else
	uint64_t global_OT_ptr = OT_ptr + m_nCounter;
#endif

	if(m_eSndOTFlav != Snd_GC_OT) {
#ifdef USE_PIPELINED_AES_NI
		for (uint64_t i = 0; i < OT_len; i++, Tptr += m_nBlockSizeBytes, bufptr += aes_key_bytes, (*global_OT_ptr)++) {
#else
		for (uint64_t i = 0; i < OT_len; i++, Tptr += m_nBlockSizeBytes, bufptr += aes_key_bytes, global_OT_ptr++) {
#endif
#ifdef DEBUG_OT_HASH_IN
			std::cout << "Hash-In for i = " << global_OT_ptr << ": " << (std::hex);
			for(uint32_t p = 0; p < rowbytelen; p++)
				std::cout << std::setw(2) << std::setfill('0') << (uint32_t) Tptr[p];
				std::cout << (std::dec) << std::endl;
#endif

#ifdef USE_PIPELINED_AES_NI
			AES_256_Key_Expansion(Tptr, &tk_aeskey);
			inblock = _mm_loadu_si128((__m128i const*)(resbuf));
			AES_encryptC(&inblock, &outblock, &tk_aeskey);
			_mm_storeu_si128((__m128i *)(bufptr), outblock);
#else
			memcpy(inbuf, &global_OT_ptr, sizeof(uint64_t));
			memcpy(inbuf+sizeof(uint64_t), Tptr, rowbytelen);
			m_cCrypt->hash_buf(resbuf, aes_key_bytes, inbuf, hashinbytelen, hash_buf);
			memcpy(bufptr, resbuf, aes_key_bytes);
#endif


#ifdef DEBUG_OT_HASH_OUT
			std::cout << "Hash-Out for i = " << global_OT_ptr << ": " << (std::hex);
			for(uint32_t p = 0; p < aes_key_bytes; p++)
				std::cout << std::setw(2) << std::setfill('0') << (uint32_t) bufptr[p];
			std::cout << (std::dec) << " (" << m_vChoices->Get<uint32_t>(global_OT_ptr * choicecodebits, choicecodebits) << ")" <<  std::endl;
#endif
		}
		//TODO: difference is in here!! (could be solved by giving the bit-length as parameter in the function call)
		//m_fMaskFct->expandMask(m_vTempOTMasks, seedbuf.GetArr(), OT_ptr, OT_len, m_nBitLength, m_cCrypt);
		m_fMaskFct->expandMask(maskbuf, seedbuf->GetArr(), 0, OT_len, m_nBitLength * diff_choicecodes, m_cCrypt);

	} else {
		for(uint64_t i = 0; i < OT_len; i++, Tptr += m_nBlockSizeBytes) {
			BitMatrixMultiplication(tmpbufb, bits_in_bytes(m_nBitLength), Tptr, m_nBaseOTs, mat_mul, tmpbuf);
			//m_vTempOTMasks.SetBits(tmpbufb, (uint64_t) (OT_ptr + i) * m_nBitLength, m_nBitLength);
			maskbuf->SetBits(tmpbufb, i * m_nBitLength, m_nBitLength);
		}
	}

	free(tmpbuf);
	free(tmpbufb);
	free(resbuf);
	free(inbuf);
	free(hash_buf);
}




void KKOTExtRec::KKSetOutput(CBitVector* maskbuf, uint64_t otid, uint64_t otlen, std::queue<mask_block*>* mask_queue,
		channel* chan) {
	mask_block* tmpblock = (mask_block*) malloc(sizeof(mask_block));
	tmpblock->startotid = otid;
	tmpblock->otlen = otlen;
	tmpblock->buf = new CBitVector();
	tmpblock->buf->Copy(maskbuf->GetArr(), 0, maskbuf->GetSize());

	//std::cout << "OTptr = " << otid << ", OT_len = " << otlen << std::endl;

	mask_queue->push(tmpblock);
	if(chan->data_available()) {
		KKReceiveAndUnMask(chan, mask_queue);
	}
}


void KKOTExtRec::KKReceiveAndUnMask(channel* chan, std::queue<mask_block*>* mask_queue) {
	uint64_t startotid, otlen, bufsize, valsize;
	uint8_t *tmpbuf, *buf;
	CBitVector vRcv;
	CBitVector mask;
	mask_block* tmpblock;
	uint32_t tmpchoice;
	uint32_t int_choicecodebits = ceil_log2(m_nint_sndvals);
	uint32_t ext_choicecodebits = ceil_log2(m_nSndVals);
	uint32_t diff_choicecodes = int_choicecodebits / ext_choicecodebits;

	// uint32_t tmpmask;
	uint8_t* tmpmaskbuf;
	uint32_t startval, endval;
	uint32_t offset = m_nint_sndvals;

	if(m_eSndOTFlav == Snd_OT) {
		startval = 0;
		endval = m_nint_sndvals;
	} else if (m_eSndOTFlav == Snd_C_OT) {
		startval = 1;
		endval = m_nint_sndvals;
	} else if(m_eSndOTFlav == Snd_R_OT) {
		startval = 1;
		endval = m_nint_sndvals - 1;
		offset = endval / (m_nSndVals-1);
	}

	//tmpbuf = (uint8_t*) malloc(bits_in_bytes(diff_choicecodes * m_nBitLength));
	tmpmaskbuf = (uint8_t*) malloc(bits_in_bytes(diff_choicecodes * m_nBitLength));

	while(chan->data_available() && !(mask_queue->empty())) {
		tmpblock = mask_queue->front();
		//Get values and unmask
		buf = chan->blocking_receive_id_len(&tmpbuf, &startotid, &otlen);//chan->blocking_receive();//rcvqueue->front();

		assert(startotid == tmpblock->startotid);
		//std::cout << " oten = " << otlen << ", tmpblock otlen = " << tmpblock.otlen << std::endl;
		assert(otlen == tmpblock->otlen);

		valsize = bits_in_bytes(otlen * m_nBitLength * diff_choicecodes);
		bufsize = valsize * m_nint_sndvals;

		vRcv.AttachBuf(tmpbuf, bufsize);

		m_vRet->Copy(*tmpblock->buf, bits_in_bytes(diff_choicecodes * startotid * m_nBitLength), valsize);
#ifdef DEBUG_KK_OTBREAKDOWN
		std::cout << "Base: ";
		m_vRet->PrintHex(0, bufsize);
#endif

		for(uint32_t i = 0; i < otlen; i++) {
			tmpchoice = m_vChoices->Get<uint32_t>((startotid + i) * int_choicecodebits, int_choicecodebits);
#ifdef DEBUG_KK_OTBREAKDOWN
			std::cout << "choice in " <<i << "-th 1-out-of-" << m_nint_sndvals << " OT: " << tmpchoice << std::endl;
#endif
			//if(tmpchoice >= startval && tmpchoice != endval) {
			if(ceil_divide(tmpchoice, offset) * offset != tmpchoice || startval == 0) {
				//std::cout << "Getting bits for i = " << i << ", tmpchoice = " << tmpchoice <<", and offset = " << offset << std::endl;
				//vRcv.GetBits(tmpmaskbuf, (tmpchoice-startval) * valsize * 8 + i * diff_choicecodes*m_nBitLength, diff_choicecodes*m_nBitLength);
				if(m_eSndOTFlav == Snd_R_OT) {
					vRcv.GetBits(tmpmaskbuf, (tmpchoice-(ceil_divide(tmpchoice, offset))) * valsize * 8 + i * diff_choicecodes*m_nBitLength, diff_choicecodes*m_nBitLength);
				} else {
					vRcv.GetBits(tmpmaskbuf, (tmpchoice-startval) * valsize * 8 + i * diff_choicecodes*m_nBitLength, diff_choicecodes*m_nBitLength);
				}
#ifdef DEBUG_KK_OTBREAKDOWN
				std::cout << "Accessing bit-address " << (tmpchoice-1) * valsize * 8 + i * diff_choicecodes*m_nBitLength << " with bit-length " << diff_choicecodes*m_nBitLength << std::endl;
#endif
			}
			else {
				memset(tmpmaskbuf, 0, bits_in_bytes(diff_choicecodes * m_nBitLength));
			}

#ifdef DEBUG_KK_OTBREAKDOWN


			std::cout << "Mask " << tmpchoice << ": "<< (std::hex);
			for(uint32_t j = 0; j < bits_in_bytes(diff_choicecodes * m_nBitLength); j++)
				std::cout << (uint32_t) m_vRet->Get<uint8_t>((startotid + i) * diff_choicecodes * m_nBitLength + j*8, 8);
			std::cout << (std::dec) << std::endl;
			//tmpmask ^= tmpblock.Get<uint32_t>(i * choicecodebits, choicecodebits);
			//m_vRet.XOR(tmpmask, (startotid + i), choicecodebits);

			std::cout << "Recv " << tmpchoice << ": "<< (std::hex);
			for(uint32_t j = 0; j < bits_in_bytes(diff_choicecodes * m_nBitLength); j++)
				std::cout << (uint32_t) tmpmaskbuf[j];
			std::cout << (std::dec) << std::endl;
			std::cout << "startotid = " << startotid << ", start = " << (startotid + i) * diff_choicecodes * m_nBitLength << ", len = " <<  diff_choicecodes * m_nBitLength << std::endl;
#endif
			//m_vRet.XORBytes(tmpmaskbuf, bits_in_bytes((startotid + i) * choicecodebits * m_nBitLength), bits_in_bytes(choicecodebits * m_nBitLength));
			m_vRet->XORBits(tmpmaskbuf, (startotid + i) * diff_choicecodes * m_nBitLength, diff_choicecodes * m_nBitLength);

#ifdef DEBUG_KK_OTBREAKDOWN
			std::cout << "Val " << tmpchoice << ": "<< (std::hex);
			for(uint32_t j = 0; j < bits_in_bytes(diff_choicecodes * m_nBitLength); j++)
				std::cout << (uint32_t) m_vRet->Get<uint8_t>((startotid + i) * diff_choicecodes * m_nBitLength + j*8, 8);
			std::cout << (std::dec) << std::endl;
#endif
		}

		mask_queue->pop();
		delete tmpblock->buf;
		free(tmpblock);
		free(buf);
	}
	vRcv.DetachBuf();
	free(tmpmaskbuf);
#ifdef DEBUG_KK_OTBREAKDOWN
	std::cout << "Final output: ";
	m_vRet->PrintHex();
#endif
}

void KKOTExtRec::KKMaskBaseOTs(CBitVector* T, CBitVector* SndBuf, uint64_t numblocks) {
	uint64_t rowbytelen = m_nBlockSizeBytes * numblocks;
	SndBuf->XORBytes(T->GetArr(), 0, rowbytelen * m_nBaseOTs);
}


void KKOTExtRec::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	//m_nSndVals = 16; //TODO hack!
	delete m_cBaseOT;
}

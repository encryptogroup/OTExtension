/*
 * kk-ot-ext-receiver.cpp
 *
 *  Created on: Aug 20, 2015
 *      Author: mzohner
 */

#include "kk-ot-ext-rec.h"


BOOL KKOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	uint32_t choicecodebitlen = ceil_log2(m_nSndVals);

	uint64_t myStartPos = id * myNumOTs;
	uint64_t myStartPos1ooN = ceil_divide(myStartPos, choicecodebitlen);
	uint64_t wd_size_bits = m_nBlockSizeBits;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	//TODO some re-formating of myNumOTs due to 1ooN OT
	uint64_t lim = myStartPos1ooN + ceil_divide(myNumOTs, choicecodebitlen);

	if(myStartPos1ooN * choicecodebitlen> m_nOTs) {
		cerr << "Thread " << id << " not doing any work to align to window size " << endl;
		return true;
	}


	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t OTwindow = NUMOTBLOCKS * wd_size_bits;
	uint64_t** rndmat;
	uint64_t processedOTs;
	channel* chan = new channel(id, m_cRcvThread, m_cSndThread);

	//counter variables
	uint64_t numblocks = ceil_divide(myNumOTs, OTsPerIteration);

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

	queue<mask_block*> mask_queue;

	CBitVector maskbuf;
	maskbuf.Create(m_nBitLength * OTwindow * choicecodebitlen);

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
	timeval tempStart, tempEnd;
#endif

	while (otid < lim) {
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		processedOTs = min(lim - otid, OTsPerIteration);
		//nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, vSnd, otid, processedOTBlocks);

#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalChoiceTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		//generate the code elements that correspond to my choice bits
		GenerateChoiceCodes(choicecodes, vSnd, otid, processedOTs);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		//MaskBaseOTs(T, vSnd, otid, processedOTBlocks);
		KKMaskBaseOTs(T, vSnd, processedOTBlocks);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMaskTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		T.Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		KKHashValues(T, seedbuf, &maskbuf, otid, processedOTs, rndmat);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		SendMasks(vSnd, chan, otid, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		//SetOutput(maskbuf, otid, OTsPerIteration, &mask_queue, chan);//ReceiveAndUnMask(chan);
		KKSetOutput(&maskbuf, otid, processedOTs, &mask_queue, chan);
		//counter += min(lim - OT_ptr, OTsPerIteration);
		otid += min(lim - otid, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
#endif

		vSnd.Reset();
		T.Reset();
	}
	//sndthread->signal_end(id);

	while(chan->is_alive() && !(mask_queue.empty()))
		KKReceiveAndUnMask(chan, &mask_queue);


	chan->synchronize_end();

	T.delCBitVector();
	vSnd.delCBitVector();
	seedbuf.delCBitVector();
	maskbuf.delCBitVector();
	if(m_eSndOTFlav==Snd_GC_OT)
		freeRndMatrix(rndmat, m_nBaseOTs);
#ifdef OTTiming
	cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Base OT Masking:\t" << totalMaskTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

	return TRUE;
}


void KKOTExtRec::GenerateChoiceCodes(CBitVector& choicecodes, CBitVector& vSnd, uint32_t startpos, uint32_t len) {
	uint32_t tmpchoice;
	uint32_t otid = startpos;
	uint32_t ncolumnsbyte = ceil_divide(len, m_nCodeWordBits) * m_nCodeWordBytes;
	uint32_t choicecodebitlen = ceil_log2(m_nSndVals);

	//cout << "vSnd In: ";
	//vSnd.PrintHex(0, ncolumnsbyte*len);
	for(uint32_t pos = 0; pos < len; pos+=m_nCodeWordBits) {

		//build blocks of 256x256 code bits
		choicecodes.Reset();
		for(uint32_t j = 0; j < min(len - pos, m_nCodeWordBits); j++, otid++) {
			tmpchoice = m_vChoices->Get<uint32_t>(otid * choicecodebitlen, choicecodebitlen);
			//cout << "otid = " << otid << ", choice = " << tmpchoice << endl;
			choicecodes.SetBytes((uint8_t*) m_vCodeWords[tmpchoice], j*m_nCodeWordBytes, m_nCodeWordBytes);
		}
		//cout << "Using codeword " << (hex) << m_vCodeWords[tmpchoice][0] << m_vCodeWords[tmpchoice][1] << (hex) <<
		//		m_vCodeWords[tmpchoice][2] << m_vCodeWords[tmpchoice][3] << (dec) << endl;

		//transpose these 256x256 code bits to match the order of the T matrix
		choicecodes.EklundhBitTranspose(m_nCodeWordBits, m_nCodeWordBits);

		//XOR these transposed choice bits blockwise on the matrix that is sent to S
		for(uint32_t j = 0; j < m_nCodeWordBits; j++) {
			vSnd.XORBytes(choicecodes.GetArr() + j * m_nCodeWordBytes, (pos >> 3) + j * ncolumnsbyte, m_nCodeWordBytes);
		}
	}
	//cout << "vSnd Out: ";
	//vSnd.PrintHex(0, ncolumnsbyte*len);
}

void KKOTExtRec::KKHashValues(CBitVector& T, CBitVector& seedbuf, CBitVector* maskbuf, uint64_t OT_ptr, uint64_t OT_len, uint64_t** mat_mul) {
	//uint32_t wd_size_bytes = m_nBlockSizeBytes;//(1 << ((ceil_log2(m_nBaseOTs)) - 3));
	uint32_t rowbytelen = bits_in_bytes(m_nBaseOTs);
	uint32_t hashinbytelen = rowbytelen + sizeof(uint64_t);
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	uint8_t* Tptr = T.GetArr();
	uint8_t* bufptr = seedbuf.GetArr();

	uint8_t* inbuf = (uint8_t*) calloc(hashinbytelen, 1);
	uint8_t* resbuf = (uint8_t*) calloc(m_cCrypt->get_hash_bytes(), 1);
	uint8_t* hash_buf = (uint8_t*) calloc(m_cCrypt->get_hash_bytes(), 1);

	uint64_t* tmpbuf = (uint64_t*) calloc(PadToMultiple(bits_in_bytes(m_nBitLength), sizeof(uint64_t)), 1);
	uint8_t* tmpbufb = (uint8_t*) calloc(bits_in_bytes(m_nBitLength), 1);

	uint32_t choicecodebits = ceil_log2(m_nSndVals);

	uint64_t global_OT_ptr = OT_ptr + m_nCounter;

	if(m_eSndOTFlav != Snd_GC_OT) {
		for (uint64_t i = 0; i < OT_len; i++, Tptr += m_nBlockSizeBytes, bufptr += aes_key_bytes, global_OT_ptr++) {
#ifdef DEBUG_OT_HASH_IN
			cout << "Hash-In for i = " << global_OT_ptr << ": " << (hex);
			for(uint32_t p = 0; p < rowbytelen; p++)
				cout << setw(2) << setfill('0') << (uint32_t) Tptr[p];
				cout << (dec) << endl;
#endif

#ifdef FIXED_KEY_AES_HASHING
			FixedKeyHashing(m_kCRFKey, bufptr, Tptr, hash_buf, i, ceil_divide(m_nBaseOTs, 8), m_cCrypt);
#else
			memcpy(inbuf, &global_OT_ptr, sizeof(uint64_t));
			memcpy(inbuf+sizeof(uint64_t), Tptr, rowbytelen);
			m_cCrypt->hash_buf(resbuf, aes_key_bytes, inbuf, hashinbytelen, hash_buf);
			memcpy(bufptr, resbuf, aes_key_bytes);
#endif


#ifdef DEBUG_OT_HASH_OUT
			cout << "Hash-Out for i = " << global_OT_ptr << ": " << (hex);
			for(uint32_t p = 0; p < aes_key_bytes; p++)
				cout << setw(2) << setfill('0') << (uint32_t) bufptr[p];
			cout << (dec) << " (" << m_vChoices.Get<uint32_t>(global_OT_ptr * choicecodebits, choicecodebits) << ")" <<  endl;
#endif
		}
		//TODO: difference is in here!! (could be solved by giving the bit-length as parameter in the function call)
		//m_fMaskFct->expandMask(m_vTempOTMasks, seedbuf.GetArr(), OT_ptr, OT_len, m_nBitLength, m_cCrypt);
		m_fMaskFct->expandMask(maskbuf, seedbuf.GetArr(), 0, OT_len, m_nBitLength * choicecodebits, m_cCrypt);

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




void KKOTExtRec::KKSetOutput(CBitVector* maskbuf, uint64_t otid, uint64_t otlen, queue<mask_block*>* mask_queue,
		channel* chan) {
	mask_block* tmpblock = (mask_block*) malloc(sizeof(mask_block));
	tmpblock->startotid = otid;
	tmpblock->otlen = otlen;
	tmpblock->buf = new CBitVector();
	tmpblock->buf->Copy(maskbuf->GetArr(), 0, maskbuf->GetSize());

	//cout << "OTptr = " << otid << ", OT_len = " << otlen << endl;

	mask_queue->push(tmpblock);
	if(chan->data_available()) {
		KKReceiveAndUnMask(chan, mask_queue);
	}
}


void KKOTExtRec::KKReceiveAndUnMask(channel* chan, queue<mask_block*>* mask_queue) {
	uint64_t startotid, otlen, bufsize, valsize;
	uint8_t *tmpbuf, *buf;
	CBitVector vRcv;
	CBitVector mask;
	mask_block* tmpblock;
	uint32_t tmpchoice;
	uint32_t choicecodebits = ceil_log2(m_nSndVals);
	uint32_t tmpmask;
	uint8_t* tmpmaskbuf;

	tmpmaskbuf = (uint8_t*) malloc(bits_in_bytes(choicecodebits * m_nBitLength));

	while(chan->data_available() && !(mask_queue->empty())) {
		tmpblock = mask_queue->front();
		//Get values and unmask
		buf = chan->blocking_receive_id_len(&tmpbuf, &startotid, &otlen);//chan->blocking_receive();//rcvqueue->front();

		assert(startotid == tmpblock->startotid);
		//cout << " oten = " << otlen << ", tmpblock otlen = " << tmpblock.otlen << endl;
		assert(otlen == tmpblock->otlen);

		valsize = bits_in_bytes(otlen * m_nBitLength * choicecodebits);
		bufsize = valsize * m_nSndVals;

		vRcv.AttachBuf(tmpbuf, bufsize);

		m_vRet->Copy(*tmpblock->buf, bits_in_bytes(choicecodebits * startotid * m_nBitLength), valsize);
#ifdef DEBUG_KK_OTBREAKDOWN
		cout << "Base: ";
		m_vRet.PrintHex(0, bufsize);
#endif

		for(uint32_t i = 0; i < otlen; i++) {
			tmpchoice = m_vChoices->Get<uint32_t>((startotid + i) * choicecodebits, choicecodebits);
#ifdef DEBUG_KK_OTBREAKDOWN
			cout << "choice in " <<i << "-th 1-out-of-" << m_nSndVals << " OT: " << tmpchoice << endl;
#endif
			if(tmpchoice != 0 && tmpchoice != m_nSndVals -1) {
				//tmpmask = vRcv.Get<uint32_t>((tmpchoice-1) * valsize * 8 + i * choicecodebits*m_nBitLength, choicecodebits*m_nBitLength);
				vRcv.GetBits(tmpmaskbuf, (tmpchoice-1) * valsize * 8 + i * choicecodebits*m_nBitLength, choicecodebits*m_nBitLength);
#ifdef DEBUG_KK_OTBREAKDOWN
				cout << "Accessing bit-address " << (tmpchoice-1) * valsize * 8 + i * choicecodebits*m_nBitLength << " with bit-length " << choicecodebits*m_nBitLength << endl;
#endif
			}
			else {
				memset(tmpmaskbuf, 0, bits_in_bytes(choicecodebits * m_nBitLength));
			}

#ifdef DEBUG_KK_OTBREAKDOWN
			cout << "Mask " << tmpchoice << ": "<< (hex);
			for(uint32_t j = 0; j < bits_in_bytes(choicecodebits * m_nBitLength); j++)
				cout << (uint32_t) tmpmaskbuf[j];
			cout << (dec) << endl;
			//tmpmask ^= tmpblock.Get<uint32_t>(i * choicecodebits, choicecodebits);
			//m_vRet.XOR(tmpmask, (startotid + i), choicecodebits);
			cout << "startotid = " << startotid << ", start = " << (startotid + i) * choicecodebits * m_nBitLength << ", len = " <<  choicecodebits * m_nBitLength << endl;
#endif
			//m_vRet.XORBytes(tmpmaskbuf, bits_in_bytes((startotid + i) * choicecodebits * m_nBitLength), bits_in_bytes(choicecodebits * m_nBitLength));
			m_vRet->XORBits(tmpmaskbuf, (startotid + i) * choicecodebits * m_nBitLength, choicecodebits * m_nBitLength);

		}
#ifdef DEBUG_KK_OTBREAKDOWN
		cout << endl << "Xc: ";
		m_vRet.PrintHex(0, valsize);
#endif
		mask_queue->pop();
		tmpblock->buf->delCBitVector();
		free(buf);
	}
	free(tmpmaskbuf);
}

void KKOTExtRec::KKMaskBaseOTs(CBitVector& T, CBitVector& SndBuf, uint64_t numblocks) {
	uint64_t rowbytelen = m_nBlockSizeBytes * numblocks;
	SndBuf.XORBytes(T.GetArr(), 0, rowbytelen * m_nBaseOTs);
}


void KKOTExtRec::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	m_nSndVals = 16; //TODO hack!
	delete m_cBaseOT;
}

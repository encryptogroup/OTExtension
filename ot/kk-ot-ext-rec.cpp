/*
 * kk-ot-ext-receiver.cpp
 *
 *  Created on: Aug 20, 2015
 *      Author: mzohner
 */

#include "kk-ot-ext-rec.h"


BOOL KKOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	uint32_t choicecodebitlen = ceil_log2(m_nSndVals);

	uint64_t myStartPos = ceil_divide(id * myNumOTs, choicecodebitlen);
	uint64_t wd_size_bits = m_nBlockSizeBits;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = ceil_divide(myStartPos + myNumOTs, choicecodebitlen);


	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t OTwindow = NUMOTBLOCKS * wd_size_bits;
	uint64_t** rndmat;
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

	uint64_t otid = myStartPos;

	queue<mask_block> mask_queue;

	CBitVector maskbuf;
	maskbuf.Create(m_nBitLength * OTwindow);

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
		GenerateChoiceCodes(choicecodes, vSnd, otid, processedOTBlocks);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		MaskBaseOTs(T, vSnd, otid, processedOTBlocks);
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
		HashValues(T, seedbuf, maskbuf, otid, min(lim - otid, OTsPerIteration), rndmat);
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
		//TODO: replace by own method
		KKSetOutput(maskbuf, otid, OTsPerIteration, &mask_queue, chan);
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

	while(chan->is_alive())
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
	for(uint32_t pos = 0; pos < len; pos+=m_nCodeWordBits) {

		//build blocks of 256x256 code bits
		choicecodes.Reset();
		for(uint32_t j = 0; j < min(len - pos, m_nCodeWordBits); j++, otid++) {
			tmpchoice = m_vChoices.Get<uint32_t>(otid * choicecodebitlen, choicecodebitlen);
			//cout << "otid = " << otid << ", choice = " << tmpchoice << endl;
#ifdef ZDEBUG
		cout << "my choice : " << tmpchoice << endl;
#endif
			choicecodes.SetBytes((uint8_t*) m_vCodeWords[tmpchoice], j*m_nCodeWordBytes, m_nCodeWordBytes);
		}

		//transpose these 256x256 code bits to match the order of the T matrix
		choicecodes.EklundhBitTranspose(m_nCodeWordBits, m_nCodeWordBits);

		//XOR these transposed choice bits blockwise on the matrix that is sent to S
		for(uint32_t j = 0; j < m_nCodeWordBits; j++) {
			vSnd.XORBytes(choicecodes.GetArr() + j * m_nCodeWordBytes, (pos >> 3) + j * ncolumnsbyte, m_nCodeWordBytes);
		}
	}
}

void KKOTExtRec::KKSetOutput(CBitVector& maskbuf, uint64_t otid, uint64_t otlen, queue<mask_block>* mask_queue,
		channel* chan) {
	uint32_t remots = min(otlen, m_nOTs - otid);

	mask_block tmpblock;
	tmpblock.startotid = otid;
	tmpblock.otlen = remots;
	tmpblock.buf.Copy(maskbuf);

	mask_queue->push(tmpblock);
	if(chan->data_available()) {
		KKReceiveAndUnMask(chan, mask_queue);
	}
}

void KKOTExtRec::KKReceiveAndUnMask(channel* chan, queue<mask_block>* mask_queue) {
	uint64_t startotid, otlen, bufsize, valsize;
	uint8_t *tmpbuf, *buf;
	CBitVector vRcv;
	CBitVector mask;
	mask_block tmpblock;
	uint32_t tmpchoice;
	uint32_t choicecodebits = ceil_log2(m_nSndVals);
	uint32_t tmpmask;

	while(chan->data_available() && !(mask_queue->empty())) {
		tmpblock = mask_queue->front();
		//Get values and unmask
		buf = chan->blocking_receive_id_len(&tmpbuf, &startotid, &otlen);//chan->blocking_receive();//rcvqueue->front();

		assert(startotid == tmpblock.startotid);
		//cout << " oten = " << otlen << ", tmpblock otlen = " << tmpblock.otlen << endl;
		assert(otlen == tmpblock.otlen);

		valsize = bits_in_bytes(otlen * m_nBitLength * choicecodebits);
		bufsize = bufsize * m_nSndVals;

		vRcv.AttachBuf(tmpbuf, bufsize);

		uint32_t remots = min(otlen, m_nOTs - startotid);
		m_vRet.Copy(tmpblock.buf, bits_in_bytes(startotid * m_nBitLength), valsize);

		for(uint32_t i = 0; i < otlen; i++) {
			tmpchoice = m_vChoices.Get<uint32_t>((startotid + i) * choicecodebits, choicecodebits);
			tmpmask = vRcv.Get<uint32_t>(tmpchoice * valsize * 8 + i * choicecodebits, choicecodebits);
			//tmpmask ^= tmpblock.Get<uint32_t>(i * choicecodebits, choicecodebits);
			m_vRet.XOR(tmpmask, (startotid + i), choicecodebits);
		}
		mask_queue->pop();
		tmpblock.buf.delCBitVector();
		free(buf);
	}
}


void KKOTExtRec::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	delete m_cBaseOT;
}

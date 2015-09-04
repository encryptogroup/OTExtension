/*
 * kk-ot-ext-sender.cpp
 *
 *  Created on: Aug 20, 2015
 *      Author: mzohner
 */

#include "kk-ot-ext-snd.h"

BOOL KKOTExtSnd::sender_routine(uint32_t id, uint64_t myNumOTs) {
	uint32_t choicecodebitlen = ceil_log2(m_nSndVals);
	uint64_t myStartPos = id * myNumOTs;
	uint64_t myStartPos1ooN = ceil_divide(myStartPos, choicecodebitlen);

	uint64_t wd_size_bits = m_nBlockSizeBits;
	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	channel* chan = new channel(id, m_cRcvThread, m_cSndThread);
	uint64_t tmpctr, tmpotlen;
	uint64_t** rndmat;
	uint64_t processedOTs;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	//TODO some re-formating of myNumOTs due to 1ooN OT
	uint64_t lim = myStartPos1ooN + ceil_divide(myNumOTs, choicecodebitlen);

	if(myStartPos1ooN * choicecodebitlen> m_nOTs) {
		cerr << "Thread " << id << " not doing any work to align to window size " << endl;
		return true;
	}

	// The vector with the received bits
#ifdef GENERATE_T_EXPLICITELY
	CBitVector vRcv(2 * m_nBaseOTs * OTsPerIteration);
#else
	CBitVector vRcv(m_nBaseOTs * OTsPerIteration);
#endif

	// Holds the reply that is sent back to the receiver
	CBitVector* vSnd;

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration * m_cCrypt->get_aes_key_bytes() * 8);
#ifdef ZDEBUG
	cout << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << endl;
#endif
	vSnd = new CBitVector[m_nSndVals];
	for (uint32_t i = 0; i < m_nSndVals; i++) {
		vSnd[i].Create(OTsPerIteration * choicecodebitlen * m_nBitLength);
	}

	// Contains the parts of the V matrix
	CBitVector Q(wd_size_bits * OTsPerIteration);

	uint64_t otid = myStartPos1ooN;

	uint8_t *rcvbuftmpptr, *rcvbufptr;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalUnMaskTime=0;
	timeval tempStart, tempEnd;
#endif

	if(m_eSndOTFlav == Snd_GC_OT) {
		uint8_t* rnd_seed = (uint8_t*) malloc(m_nSymSecParam);
		m_cCrypt->gen_rnd(rnd_seed, m_nSymSecParam);
		chan->send(rnd_seed, m_nSymSecParam);
		initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
		fillRndMatrix(rnd_seed, rndmat, m_nBitLength, m_nBaseOTs, m_cCrypt);
		free(rnd_seed);
	}

	while (otid < lim) //do while there are still transfers missing
	{
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		processedOTs = min(lim - otid, OTsPerIteration);

#ifdef ZDEBUG
		cout << "Processing block " << nProgress << " with length: " << OTsPerIteration << ", and limit: " << lim << endl;
#endif

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		ReceiveMasks(vRcv, chan, OTsPerIteration);

#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		BuildQMatrix(Q, otid, processedOTBlocks);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		UnMaskBaseOTs(Q, vRcv, processedOTBlocks);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalUnMaskTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		Q.Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		KKHashValues(Q, seedbuf, vSnd, otid, processedOTs, rndmat);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		KKMaskAndSend(vSnd, otid, processedOTs, chan);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		otid += processedOTs;
		Q.Reset();
	}

	vRcv.delCBitVector();
	chan->synchronize_end();

	Q.delCBitVector();

	for (uint32_t i = 0; i < m_nSndVals; i++)
		vSnd[i].delCBitVector();
	delete vSnd;

	if(m_eSndOTFlav==Snd_GC_OT)
		freeRndMatrix(rndmat, m_nBaseOTs);

#ifdef OTTiming
	cout << "Sender time benchmark for performing " << myNumOTs << " OTs (" << lim-myStartPos1ooN <<
			" 1ooN) on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Unmasking values:\t" << totalUnMaskTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

	delete chan;

	return TRUE;
}


void KKOTExtSnd::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	m_nSndVals = 16; //TODO hack!
	delete m_cBaseOT;
}



void KKOTExtSnd::KKHashValues(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint64_t OT_ptr, uint64_t OT_len, uint64_t** mat_mul) {
	uint64_t numhashiters = ceil_divide(m_nBitLength, m_cCrypt->get_hash_bytes());
	uint32_t rowbytelen = bits_in_bytes(m_nBaseOTs);
	uint32_t hashinbytelen = rowbytelen + sizeof(uint64_t);
	uint32_t hashoutbitlen = ceil_log2(m_nSndVals);
	uint64_t wd_size_bytes = m_nBlockSizeBytes;//1 << (ceil_log2(m_nBaseOTs) - 3);
	uint32_t u;
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();
	uint32_t choicebitlen = ceil_log2(m_nSndVals);

	uint64_t* Qptr = (uint64_t*) Q.GetArr();

	uint8_t** sbp = (uint8_t**) malloc(sizeof(uint8_t*) * m_nSndVals);
	uint8_t* inbuf = (uint8_t*) calloc(hashinbytelen, 1);
	uint8_t* resbuf = (uint8_t*) calloc(m_cCrypt->get_hash_bytes(), 1);
	uint8_t* hash_buf = (uint8_t*) calloc(m_cCrypt->get_hash_bytes(), 1);

	uint64_t* tmpbuf = (uint64_t*) calloc(PadToMultiple(bits_in_bytes(m_nBitLength), sizeof(uint64_t)), 1);
	uint8_t* tmpbufb = (uint8_t*) calloc(bits_in_bytes(m_nBitLength), 1);

	uint64_t global_OT_ptr = OT_ptr + m_nCounter;
	CBitVector mask(m_nCodeWordBits);

	for (u = 0; u < m_nSndVals; u++)
		sbp[u] = seedbuf[u].GetArr();

	for (uint64_t i = 0; i < OT_len; global_OT_ptr++, i++, Qptr += 2) {
		for (u = 0; u < m_nSndVals; u++) {
			mask.Copy(m_vU, 0, rowbytelen);
			mask.ANDBytes((uint8_t*) m_vCodeWords[u], 0, rowbytelen);
			mask.XORBytes(Q.GetArr() + i * rowbytelen, rowbytelen);

#ifdef DEBUG_OT_HASH_IN
			cout << "Hash-In for i = " << global_OT_ptr << ", u = " << u << ": " << (hex);
			for(uint32_t p = 0; p < rowbytelen; p++)
				cout << setw(2) << setfill('0') << (uint32_t) mask.GetArr()[p];
			cout << (dec) << endl;
			//cout << "Using codeword " << (hex) << m_vCodeWords[u][0] << m_vCodeWords[u][1] << (hex) << m_vCodeWords[u][2] << m_vCodeWords[u][3] << (dec) << endl;

#endif

			if(m_eSndOTFlav != Snd_GC_OT) {
#ifdef FIXED_KEY_AES_HASHING
				FixedKeyHashing(m_kCRFKey, sbp[u], (BYTE*) Qptr, hash_buf, i, hashinbytelen, m_cCrypt);
#else
				memcpy(inbuf, &global_OT_ptr, sizeof(uint64_t));
				//memcpy(inbuf+sizeof(uint64_t), Q.GetArr() + i * wd_size_bytes, rowbytelen);
				memcpy(inbuf+sizeof(uint64_t), mask.GetArr(), rowbytelen);
				m_cCrypt->hash_buf(resbuf, aes_key_bytes, inbuf, hashinbytelen, hash_buf);
				memcpy(sbp[u], resbuf, aes_key_bytes);
				//snd_buf[u].SetBits(resbuf, i * hashoutbitlen, hashoutbitlen);
			} else {
				//TODO: mecr has not been tested with KK-OT!!
				BitMatrixMultiplication(tmpbufb, bits_in_bytes(hashoutbitlen), mask.GetArr(), m_nBaseOTs, mat_mul, tmpbuf);
				//BitMatrixMultiplication(tmpbufb, bits_in_bytes(m_nBitLength), Q.GetArr() + i * wd_size_bytes, m_nBaseOTs, mat_mul, tmpbuf);
				//m_vValues[u].SetBits(tmpbufb, (OT_ptr + i)* m_nBitLength, m_nBitLength);
				snd_buf[u].SetBits(tmpbufb, i * hashoutbitlen, hashoutbitlen);
					//m_vTempOTMasks.SetBytes(tmpbufb, (uint64_t) (OT_ptr + i) * aes_key_bytes, (uint64_t) aes_key_bytes);
				//m_vValues[u].SetBytes(Q.GetArr() + i * wd_size_bytes, (OT_ptr + i)* wd_size_bytes, rowbytelen);
			}
#endif

#ifdef DEBUG_OT_HASH_OUT
			cout << "Hash-Out for i = " << global_OT_ptr << ", u = " << u << ": " << (hex);
			for(uint32_t p = 0; p < aes_key_bytes; p++)
				cout << setw(2) << setfill('0') << (uint32_t) sbp[u][p];
			cout << (dec) << endl;
#endif
			sbp[u]+=m_cCrypt->get_aes_key_bytes();
		}
	}

	//TODO: difference is in here!! (could be solved by giving the bit-length as parameter in the function call)
	for (uint32_t u = 0; u < m_nSndVals; u++) {
		m_fMaskFct->expandMask(&snd_buf[u], seedbuf[u].GetArr(), 0, OT_len, m_nBitLength * choicebitlen, m_cCrypt);
		//cout << "Mask " << u << ": ";
		//snd_buf[u].PrintHex();
	}

	//m_vValues[0].PrintHex();
	//m_vValues[1].PrintHex();

	free(resbuf);
	free(inbuf);
	free(sbp);
	free(hash_buf);
	free(tmpbuf);
	free(tmpbufb);
}


void KKOTExtSnd::KKMaskAndSend(CBitVector* snd_buf, uint64_t OT_ptr, uint64_t OT_len, channel* chan) {
	//m_fMaskFct->Mask(OT_ptr, OT_len, m_vValues, snd_buf, m_eSndOTFlav);

	uint32_t choicecodebits = ceil_log2(m_nSndVals);
	uint64_t valsize = bits_in_bytes(OT_len * m_nBitLength * choicecodebits);
	uint64_t bufsize = valsize * (m_nSndVals-2); //For R-OT
	uint8_t* buf;
	buf = (uint8_t*) malloc(bufsize);
	CBitVector tmpmask(valsize * 8);
	CBitVector* snd_buf_ptr;

	//Define the X0 values as the output of 0 and the X1 values as output of m_nSndVals-1 (only 1 values)
	m_vValues[0]->SetBytes(snd_buf[0].GetArr(), bits_in_bytes(OT_ptr * choicecodebits * m_nBitLength), valsize);
	m_vValues[1]->SetBytes(snd_buf[m_nSndVals-1].GetArr(), bits_in_bytes(OT_ptr * choicecodebits * m_nBitLength), valsize);

#ifdef DEBUG_KK_OTBREAKDOWN
	cout << endl << "X0: ";
	m_vValues[0].PrintHex(0, valsize);
	cout << "X1: ";
	m_vValues[1].PrintHex(0, valsize);
#endif

	uint8_t* tmpbuf = (uint8_t*) malloc(bits_in_bytes(m_nBitLength));
	for(uint32_t i = 1; i < m_nSndVals-1; i++) {
		tmpmask.Reset();
		for(uint32_t j = 0; j < choicecodebits; j++) {
			//write the value of snd_buf[0] or snd_buf[1] in every choicecodebits position
			snd_buf_ptr = m_vValues[((i>>j) & 0x01)];
			for(uint32_t o = 0; o < OT_len; o++) {
					memset(tmpbuf, 0, bits_in_bytes(m_nBitLength));
					snd_buf_ptr->GetBits(tmpbuf, (OT_ptr+o)*choicecodebits*m_nBitLength+j*m_nBitLength, m_nBitLength);
					tmpmask.SetBits(tmpbuf, o*choicecodebits*m_nBitLength+j*m_nBitLength, m_nBitLength);
					//tmpmask.SetBit(i*choicecodebits + o, snd_buf_ptr->GetBit(i*choicecodebits + o));
			}
		}
#ifdef DEBUG_KK_OTBREAKDOWN
		cout << "Val " << i << ": ";
		tmpmask.PrintHex(0, valsize);
		cout << "Mask " << i << ": ";
		snd_buf[i].PrintHex(0, valsize);
#endif
		tmpmask.XORBytes(snd_buf[i].GetArr(), 0, valsize);
#ifdef DEBUG_KK_OTBREAKDOWN
		cout << "Res " << i << ": ";
		tmpmask.PrintHex(0, valsize);
#endif

		memcpy(buf + (i-1) * valsize, tmpmask.GetArr(), valsize);
	}

	chan->send_id_len(buf, bufsize, OT_ptr, OT_len);
	free(buf);
	free(tmpbuf);
	tmpmask.delCBitVector();
}

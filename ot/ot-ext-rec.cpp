/*
 * ot-extension-receiver.cpp
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */
#include "ot-ext-rec.h"

BOOL OTExtRec::receive(uint64_t numOTs, uint64_t bitlength, CBitVector& choices, CBitVector& ret,
		eot_flavor type, uint32_t numThreads, MaskingFunction* unmaskfct) {
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_nChoices = choices;
	m_nRet = ret;
	m_eOTFlav = type;
	m_fMaskFct = unmaskfct;
	return start_receive(numThreads);
}
;

//Initialize and start numThreads OTSenderThread
BOOL OTExtRec::start_receive(uint32_t numThreads) {
	if (m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint64_t wd_size_bits = m_nBlockSizeBits;//1 << (ceil_log2(m_nBaseOTs));
	uint64_t internal_numOTs = ceil_divide(PadToMultiple(m_nOTs, wd_size_bits), numThreads);

	//Create temporary result buf to which the threads write their temporary masks
	m_vTempOTMasks.Create(internal_numOTs * numThreads * m_nBitLength);

	sndthread->Start();
	rcvthread->Start();

	vector<OTReceiverThread*> rThreads(numThreads);
	for (uint32_t i = 0; i < numThreads; i++) {
		rThreads[i] = new OTReceiverThread(i, internal_numOTs, this);
		rThreads[i]->Start();
	}

	for (uint32_t i = 0; i < numThreads; i++) {
		rThreads[i]->Wait();
	}

	sndthread->signal_end(OT_ADMIN_CHANNEL);

	m_nCounter += m_nOTs;

	for (uint32_t i = 0; i < numThreads; i++)
		delete rThreads[i];

	if (m_eOTFlav == R_OT) {
		m_nRet.Copy(m_vTempOTMasks.GetArr(), 0, ceil_divide(m_nOTs * m_nBitLength, 8));
		m_vTempOTMasks.delCBitVector();
	}

#ifdef VERIFY_OT
	//Wait for the signal of the corresponding sender thread
	verifyOT(m_nOTs);
#endif

	return true;
}



void OTExtRec::BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint64_t numblocks, uint64_t ctr) {
	uint8_t* ctr_buf = (uint8_t*) malloc (AES_BYTES);
	uint64_t* counter = (uint64_t*) ctr_buf;
	uint64_t tempctr = (*counter);
	uint64_t wd_size_bytes = m_nBlockSizeBytes;//1 << (ceil_log2(m_nBaseOTs) - 3);
	uint64_t rowbytelen = wd_size_bytes * numblocks;
	uint64_t iters = rowbytelen / AES_BYTES;

	uint8_t* Tptr = T.GetArr();
	uint8_t* sndbufptr = SndBuf.GetArr();
	uint8_t* choiceptr;

	AES_KEY_CTX* seedptr = m_vBaseOTKeys;
	*counter = ctr;

	for (uint32_t k = 0; k < m_nBaseOTs; k++) {
		for (uint32_t b = 0; b < iters; b++, (*counter)++) {
			m_cCrypt->encrypt(seedptr + 2 * k, Tptr, ctr_buf, AES_BYTES);
#ifdef DEBUG_MALICIOUS
			cout << "correct: Tka = " << k << ": " << (hex) << ((uint64_t*) Tptr)[0] << ((uint64_t*) Tptr)[1] << (hex) << endl;
#endif
			Tptr += AES_BYTES;

			m_cCrypt->encrypt(seedptr + (2 * k) + 1, sndbufptr, ctr_buf, AES_BYTES);
#ifdef DEBUG_MALICIOUS
			cout << "correct: Tkb = " << k << ": " << (hex) << ((uint64_t*) sndbufptr)[0] << ((uint64_t*) sndbufptr)[1] << (hex) << endl;
#endif
			sndbufptr += AES_BYTES;
		}
#ifdef DEBUG_OT_SEED_EXPANSION
		cout << "X0[" << k << "]: " << (hex);
		for(uint64_t i = 0; i < AES_BYTES * iters; i++) {
			cout << (uint32_t) (Tptr-AES_BYTES*iters)[i];
		}
		cout << (dec) << endl;
		cout << "X1[" << k << "]: " << (hex);
		for(uint64_t i = 0; i < AES_BYTES * iters; i++) {
			cout << (uint32_t) (sndbufptr-AES_BYTES*iters)[i];
		}
		cout << (dec) << endl;
#endif
		(*counter) = tempctr;
	}

	choiceptr = m_nChoices.GetArr() + ceil_divide(ctr, 8);
	for (uint32_t k = 0; k < m_nBaseOTs; k++) {
		SndBuf.XORBytesReverse(choiceptr, k * rowbytelen, rowbytelen);
	}

	SndBuf.XORBytes(T.GetArr(), 0, rowbytelen * m_nBaseOTs);
	free(ctr_buf);
}

void OTExtRec::HashValues(CBitVector& T, CBitVector& seedbuf, uint64_t ctr, uint64_t processedOTs) {
	uint32_t wd_size_bytes = m_nBlockSizeBytes;//(1 << ((ceil_log2(m_nBaseOTs)) - 3));
	uint32_t rowbytelen = bits_in_bytes(m_nBaseOTs);
	uint32_t hashinbytelen = rowbytelen + sizeof(uint64_t);
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	uint8_t* Tptr = T.GetArr();
	uint8_t* bufptr = seedbuf.GetArr();

	uint8_t* inbuf = (uint8_t*) malloc(hashinbytelen);
	uint8_t* resbuf = (uint8_t*) malloc(m_cCrypt->get_hash_bytes());



	for (uint64_t i = ctr; i < ctr + processedOTs; i++, Tptr += wd_size_bytes, bufptr += aes_key_bytes) {
#ifdef DEBUG_OT_HASH
		cout << "Hash-In for i = " << i << ": " << (hex);
		for(uint32_t p = 0; p < rowbytelen; p++)
			cout << (uint32_t) Tptr[p];
		cout << (dec) << endl;
#endif

#ifdef FIXED_KEY_AES_HASHING
		FixedKeyHashing(m_kCRFKey, bufptr, Tptr, hash_buf, i, ceil_divide(m_nBaseOTs, 8), m_cCrypt);
#else
		//TODO replace hash_ctr routine by a simply hash for efficiency reasons
		//m_cCrypt->hash_ctr(bufptr, AES_KEY_BYTES, Tptr, hashinbytelen, i);
		memcpy(inbuf, &i, sizeof(uint64_t));
		memcpy(inbuf+sizeof(uint64_t), Tptr, rowbytelen);
		m_cCrypt->hash(resbuf, aes_key_bytes, inbuf, hashinbytelen);
		//m_cCrypt->hash_ctr(hash_buf, AES_KEY_BYTES, hash_buf,  hashinbytelen, i);
		memcpy(bufptr, resbuf, aes_key_bytes);
#endif

	}

#ifndef HIGH_SPEED_ROT_LT
	m_fMaskFct->expandMask(m_vTempOTMasks, seedbuf.GetArr(), ctr, processedOTs, m_nBitLength, m_cCrypt);
#endif
	free(resbuf);
	free(inbuf);
}


void OTExtRec::ReceiveAndUnMask(queue<uint8_t*> *rcvqueue) {
	if (m_eOTFlav == R_OT || m_eOTFlav == GC_OT)
		return;

	uint64_t startotid, otlen, buflen;
	uint8_t *tmpbuf, *buf;
	CBitVector vRcv;
	while(!rcvqueue->empty()) {
		//Get values and unmask
		buf = rcvqueue->front();
		rcvqueue->pop();
		tmpbuf = buf;
		//the first (sizeof(uint64_t)) bytes are the startotid
		startotid = *((uint64_t*) tmpbuf);
		tmpbuf += sizeof(uint64_t);
		//the second (sizeof(uint64_t)) bytes are the otlen
		otlen = *((uint64_t*) tmpbuf);
		tmpbuf += sizeof(uint64_t);
		//the remaining bytes are the ot data

		buflen = ceil_divide(otlen * m_nBitLength, 8);
		if (m_eOTFlav == OT)
			buflen = buflen * m_nSndVals;
		vRcv.AttachBuf(tmpbuf, buflen);

		m_fMaskFct->UnMask(startotid, otlen, m_nChoices, m_nRet, vRcv, m_vTempOTMasks, m_eOTFlav);

		free(buf);
	}

}

/*void OTExtRec::ReceiveAndProcess(uint32_t numThreads) {
	uint32_t progress = 0;
	uint32_t wd_size_bits = 1 << (ceil_log2(m_nBaseOTs));
	uint32_t threadOTs = ceil_divide(PadToMultiple(m_nOTs, wd_size_bits), numThreads);
	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(threadOTs, wd_size_bits));
	uint32_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint32_t processedOTs;
	uint32_t otid;
	uint32_t rcvbytes;
	CBitVector vRcv;
	uint32_t csockid = 0;

#ifdef OTTiming
	double totalUnmaskTime = 0, totalCheckTime = 0;
	timeval tempStart, tempEnd;
#endif

	if (m_eOTFlav == OT)
		vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	else if (m_eOTFlav == C_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength);
	else if (m_eOTFlav == R_OT)
		return;

	while (progress < m_nOTs) {
		m_vSockets[csockid].Receive((BYTE*) &otid, sizeof(uint32_t));
		m_vSockets[csockid].Receive((BYTE*) &processedOTs, sizeof(uint32_t));
#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		if (m_eOTFlav == OT || m_eOTFlav == C_OT) {
			rcvbytes = ceil_divide(processedOTs * m_nBitLength, 8);
			if (m_eOTFlav == OT)
				rcvbytes = rcvbytes * m_nSndVals;
			rcvbytes = m_vSockets[csockid].Receive(vRcv.GetArr(), rcvbytes);

			m_fMaskFct->UnMask(otid, processedOTs, m_nChoices, m_nRet, vRcv, m_vTempOTMasks, m_eOTFlav);
#ifdef OTTiming
			gettimeofday(&tempEnd, NULL);
			totalUnmaskTime += getMillies(tempStart, tempEnd);
#endif
		}
		progress += processedOTs;
	}

#ifdef OTTiming
	cout << "Total time spent processing received data: " << totalUnmaskTime << " ms" << endl;
#endif

	vRcv.delCBitVector();
}*/

BOOL OTExtRec::verifyOT(uint64_t NumOTs) {
	cout << "Verifying OT" << endl;
	CBitVector vRcvX0(NUMOTBLOCKS * AES_BITS * m_nBitLength);
	CBitVector vRcvX1(NUMOTBLOCKS * AES_BITS * m_nBitLength);
	CBitVector* Xc;
	uint64_t processedOTBlocks, otlen, otstart;
	uint32_t bytelen = ceil_divide(m_nBitLength, 8);
	uint8_t* tempXc = (uint8_t*) malloc(bytelen);
	uint8_t* tempRet = (uint8_t*) malloc(bytelen);
	BYTE resp;
	CEvent* rcvev= new CEvent;
	CEvent* finev = new CEvent;

	uint8_t *bufa, *bufb, *tmpbuf;

	queue<uint8_t*>* rcvqueue = rcvthread->add_listener(0, rcvev, finev);

	for (uint64_t i = 0; i < NumOTs;) {
		//processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(NumOTs - i, AES_BITS));
		//while(!rcvqueue->empty()) {
			/*buf = rcvqueue->front();
			rcvqueue->pop();
			tmpbuf = buf;
			otstart = *((uint64_t*) tmpbuf);
			tmpbuf+=sizeof(uint64_t);
			otlen = *((uint64_t*) tmpbuf);
			tmpbuf+=sizeof(uint64_t);*/
		while(rcvqueue->size() < 2)
			rcvev->Wait();

		bufa = rcvqueue->front();
		rcvqueue->pop();
		tmpbuf = bufa;
		otstart = *((uint64_t*) tmpbuf);
		tmpbuf+=sizeof(uint64_t);
		otlen = *((uint64_t*) tmpbuf);
		tmpbuf+=sizeof(uint64_t);
		vRcvX0.AttachBuf(tmpbuf, bits_in_bytes(otlen * m_nBitLength));

		bufb = rcvqueue->front();
		rcvqueue->pop();
		tmpbuf = bufb;
		otstart = *((uint64_t*) tmpbuf);
		tmpbuf+=sizeof(uint64_t);
		otlen = *((uint64_t*) tmpbuf);
		tmpbuf+=sizeof(uint64_t);
		vRcvX1.AttachBuf(tmpbuf, bits_in_bytes(otlen * m_nBitLength));

		for (uint64_t j = 0; j < otlen && i < NumOTs; j++, i++) {
			if (m_nChoices.GetBitNoMask(i) == 0)
				Xc = &vRcvX0;
			else
				Xc = &vRcvX1;

			Xc->GetBits(tempXc, j * m_nBitLength, m_nBitLength);
			m_nRet.GetBits(tempRet, i * m_nBitLength, m_nBitLength);
			for (uint64_t k = 0; k < bytelen; k++) {
				if (tempXc[k] != tempRet[k]) {
					cout << "Error at position i = " << i << ", k = " << k << ", with X" << (hex) << (uint32_t) m_nChoices.GetBitNoMask(i) << " = " << (uint32_t) tempXc[k]
							<< " and res = " << (uint32_t) tempRet[k] << (dec) << endl;
					resp = 0x00;
					sndthread->add_snd_task(0, (uint64_t) 1, &resp);
					return false;
				}
			}
		}


		resp = 0x01;
		cout << "Sending resp = " << (uint32_t) resp << endl;
		sndthread->add_snd_task(0, (uint64_t) 1, &resp);
		cout << "Freeing bufs" << endl;
		free(bufa);
		free(bufb);
	}



	cout << "OT Verification successful" << endl;

	finev->Wait();

//	vRcvX0.delCBitVector();
//	vRcvX1.delCBitVector();

	free(tempXc);
	free(tempRet);
	delete rcvev;
	delete finev;

	return true;
}

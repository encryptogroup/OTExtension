/*
 * ot-extension-receiver.cpp
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */
#include "ot-ext-rec.h"

BOOL OTExtRec::receive(uint64_t numOTs, uint64_t bitlength, CBitVector& choices, CBitVector& ret,
		snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numThreads, MaskingFunction* unmaskfct) {
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_nChoices = choices;
	m_nRet = ret;
	m_eSndOTFlav = stype;
	m_eRecOTFlav = rtype;
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

	//sndthread->Start();
	//rcvthread->Start();

	vector<OTReceiverThread*> rThreads(numThreads);
	for (uint32_t i = 0; i < numThreads; i++) {
		rThreads[i] = new OTReceiverThread(i, internal_numOTs, this);
		rThreads[i]->Start();
	}

	for (uint32_t i = 0; i < numThreads; i++) {
		rThreads[i]->Wait();
	}

	m_nCounter += m_nOTs;

	for (uint32_t i = 0; i < numThreads; i++)
		delete rThreads[i];

	if (m_eSndOTFlav == Snd_R_OT || m_eSndOTFlav == Snd_GC_OT) {
		m_nRet.Copy(m_vTempOTMasks.GetArr(), 0, ceil_divide(m_nOTs * m_nBitLength, 8));
		m_vTempOTMasks.delCBitVector();
	}

#ifdef VERIFY_OT
	//Wait for the signal of the corresponding sender thread
	verifyOT(m_nOTs);
#endif

	return true;
}



void OTExtRec::BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint64_t OT_ptr, uint64_t numblocks) {
	uint8_t* ctr_buf = (uint8_t*) calloc (AES_BYTES, sizeof(uint8_t));
	uint64_t* counter = (uint64_t*) ctr_buf;

	uint64_t wd_size_bytes = m_nBlockSizeBytes;//1 << (ceil_log2(m_nBaseOTs) - 3);
	uint64_t rowbytelen = wd_size_bytes * numblocks;
	uint64_t iters = rowbytelen / AES_BYTES;

	uint8_t* Tptr = T.GetArr();
	uint8_t* sndbufptr = SndBuf.GetArr();
	uint8_t* choiceptr;

	AES_KEY_CTX* seedptr = m_vBaseOTKeys;
	uint64_t global_OT_ptr = OT_ptr + m_nCounter;

	for (uint32_t k = 0; k < m_nBaseOTs; k++) {
		*counter = global_OT_ptr;

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
		cout << (dec) << " (" << (*counter)-iters << ")" <<endl;
		cout << "X1[" << k << "]: " << (hex);
		for(uint64_t i = 0; i < AES_BYTES * iters; i++) {
			cout << (uint32_t) (sndbufptr-AES_BYTES*iters)[i];
		}
		cout << (dec) << " (" << (*counter)-iters << ")" <<endl;
#endif
	}

	free(ctr_buf);
}

void OTExtRec::MaskBaseOTs(CBitVector& T, CBitVector& SndBuf, uint64_t OTid, uint64_t numblocks) {
	uint64_t rowbytelen = m_nBlockSizeBytes * numblocks;
	uint8_t* choiceptr = m_nChoices.GetArr() + ceil_divide(OTid, 8);
	uint32_t startrow = 0;

	if(m_eRecOTFlav == Rec_R_OT) {
		startrow = 1;
		m_nChoices.SetXOR(SndBuf.GetArr(), T.GetArr(), ceil_divide(OTid, 8), rowbytelen);
	}
	for (uint32_t k = startrow; k < m_nBaseOTs; k++) {
		SndBuf.XORBytesReverse(choiceptr, k * rowbytelen, rowbytelen);
	}

	SndBuf.XORBytes(T.GetArr()+startrow*rowbytelen, startrow*rowbytelen, rowbytelen * (m_nBaseOTs-startrow));
}


void OTExtRec::SendMasks(CBitVector Sndbuf, channel* chan, uint64_t OTid, uint64_t processedOTs) {
	uint64_t nSize = bits_in_bytes(m_nBaseOTs * processedOTs);
	uint8_t* bufptr = Sndbuf.GetArr();

	if(m_eRecOTFlav == Rec_R_OT) {
		nSize = bits_in_bytes((m_nBaseOTs-1) * processedOTs);
		bufptr = Sndbuf.GetArr() + ceil_divide(processedOTs, 8);
	}
	chan->send_id_len(bufptr, nSize, OTid, processedOTs);
}


void OTExtRec::HashValues(CBitVector& T, CBitVector& seedbuf, uint64_t OT_ptr, uint64_t OT_len) {
	//uint32_t wd_size_bytes = m_nBlockSizeBytes;//(1 << ((ceil_log2(m_nBaseOTs)) - 3));
	uint32_t rowbytelen = bits_in_bytes(m_nBaseOTs);
	uint32_t hashinbytelen = rowbytelen + sizeof(uint64_t);
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	uint8_t* Tptr = T.GetArr();
	uint8_t* bufptr = seedbuf.GetArr();

	uint8_t* inbuf = (uint8_t*) malloc(hashinbytelen);
	uint8_t* resbuf = (uint8_t*) malloc(m_cCrypt->get_hash_bytes());
	uint8_t* hash_buf = (uint8_t*) malloc(m_cCrypt->get_hash_bytes());

	uint64_t global_OT_ptr = OT_ptr + m_nCounter;
	if(m_eSndOTFlav != Snd_GC_OT) {
		for (uint64_t i = 0; i < OT_len; i++, Tptr += m_nBlockSizeBytes, bufptr += aes_key_bytes, global_OT_ptr++) {
#ifdef DEBUG_OT_HASH_IN
			cout << "Hash-In for i = " << global_OT_ptr << ": " << (hex);
			for(uint32_t p = 0; p < rowbytelen; p++)
				cout << (uint32_t) Tptr[p];
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
				cout << (uint32_t) bufptr[p];
			cout << (dec) << endl;
#endif
		}
#ifndef HIGH_SPEED_ROT_LT
		m_fMaskFct->expandMask(m_vTempOTMasks, seedbuf.GetArr(), OT_ptr, OT_len, m_nBitLength, m_cCrypt);
#endif

	} else {
		for(uint64_t i = 0; i < OT_len; i++, Tptr += m_nBlockSizeBytes, bufptr += aes_key_bytes) {
			memcpy(bufptr, Tptr, rowbytelen);
		}
		//TODO: implement a bit-matrix multiplication here. For now assume that nBaseOTs == outputbitlen and simply copy
		bufptr  = seedbuf.GetArr();
		for(uint64_t i = 0; i < OT_len; i++, bufptr+=AES_KEY_BYTES) {
			m_vTempOTMasks.SetBytes(bufptr, (uint64_t) (OT_ptr + i) * aes_key_bytes, (uint64_t) aes_key_bytes);
		}
	}


	free(resbuf);
	free(inbuf);
	free(hash_buf);
}


void OTExtRec::ReceiveAndUnMask(channel* chan) {
	if (m_eSndOTFlav == Snd_R_OT || m_eSndOTFlav == Snd_GC_OT)
		return;

	uint64_t startotid, otlen, buflen;
	uint8_t *tmpbuf, *buf;
	CBitVector vRcv;
	while(chan->data_available()) {
		//Get values and unmask
		buf = chan->blocking_receive();//rcvqueue->front();
		//rcvqueue->pop();
		tmpbuf = buf;
		//the first (sizeof(uint64_t)) bytes are the startotid
		startotid = *((uint64_t*) tmpbuf);
		tmpbuf += sizeof(uint64_t);
		//the second (sizeof(uint64_t)) bytes are the otlen
		otlen = *((uint64_t*) tmpbuf);
		tmpbuf += sizeof(uint64_t);
		//the remaining bytes are the ot data

		buflen = ceil_divide(otlen * m_nBitLength, 8);
		if (m_eSndOTFlav == Snd_OT)
			buflen = buflen * m_nSndVals;
		vRcv.AttachBuf(tmpbuf, buflen);

		m_fMaskFct->UnMask(startotid, otlen, m_nChoices, m_nRet, vRcv, m_vTempOTMasks, m_eSndOTFlav);

		free(buf);
	}

}

BOOL OTExtRec::verifyOT(uint64_t NumOTs) {
	cout << "Verifying OT" << endl;
	CBitVector* vRcvX = new CBitVector[2];//(CBitVector*) malloc(sizeof(CBitVector)*m_nSndVals);
	vRcvX[0].Create(NUMOTBLOCKS * AES_BITS * m_nBitLength);
	vRcvX[1].Create(NUMOTBLOCKS * AES_BITS * m_nBitLength);
	CBitVector* Xc;
	uint64_t processedOTBlocks, otlen, otstart;
	uint32_t bytelen = ceil_divide(m_nBitLength, 8);
	uint8_t* tempXc = (uint8_t*) malloc(bytelen);
	uint8_t* tempRet = (uint8_t*) malloc(bytelen);
	uint8_t** buf = (uint8_t**) malloc(sizeof(uint8_t*) * m_nSndVals);
	channel* chan = new channel(0, m_cRcvThread, m_cSndThread);
	uint8_t *tmpbuf;
	BYTE resp;


	for (uint64_t i = 0; i < NumOTs;) {
		for(uint64_t j = 0; j < m_nSndVals; j++) {
			buf[j] = chan->blocking_receive_id_len(&tmpbuf, &otstart, &otlen);
			vRcvX[j].AttachBuf(tmpbuf, bits_in_bytes(otlen * m_nBitLength));
		}

		for (uint64_t j = 0; j < otlen && i < NumOTs; j++, i++) {
			if (m_nChoices.GetBitNoMask(i) == 0)
				Xc = &vRcvX[0];
			else
				Xc = &vRcvX[1];

			Xc->GetBits(tempXc, j * m_nBitLength, m_nBitLength);
			m_nRet.GetBits(tempRet, i * m_nBitLength, m_nBitLength);
			for (uint64_t k = 0; k < bytelen; k++) {
				if (tempXc[k] != tempRet[k]) {
					cout << "Error at position i = " << i << ", k = " << k << ", with X" << (hex) << (uint32_t) m_nChoices.GetBitNoMask(i) << " = " << (uint32_t) tempXc[k]
							<< " and res = " << (uint32_t) tempRet[k] << (dec) << endl;
					resp = 0x00;
					chan->send(&resp, 1);

					chan->synchronize_end();
					return false;
				}
			}
		}

		resp = 0x01;
		chan->send(&resp, (uint64_t) 1);

		for(uint64_t j = 0; j < m_nSndVals; j++) {
			free(buf[j]);
		}
	}

	cout << "OT Verification successful" << endl;

	chan->synchronize_end();
	cout << "synchronized done" << endl;

	delete chan;
	free(tempXc);
	free(tempRet);
	free(buf);

	delete vRcvX;
	return true;
}



void OTExtRec::ComputePKBaseOTs() {
	channel* chan = new channel(0, m_cRcvThread, m_cSndThread);
	uint8_t* pBuf = (uint8_t*) malloc(m_cCrypt->get_hash_bytes() * m_nBaseOTs * m_nSndVals);
	uint8_t* keyBuf = (uint8_t*) malloc(m_cCrypt->get_aes_key_bytes() * m_nBaseOTs * m_nSndVals);

#ifdef OTTiming
	timeval np_begin, np_end;
	gettimeofday(&np_begin, NULL);
#endif
	m_cBaseOT->Sender(m_nSndVals, m_nBaseOTs, chan, pBuf);
#ifdef OTTiming
	gettimeofday(&np_end, NULL);
	printf("Time for performing the base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif

	//Key expansion
	uint8_t* pBufIdx = pBuf;
	for(int i=0; i<m_nBaseOTs * m_nSndVals; i++ )
	{
		memcpy(keyBuf + i * m_cCrypt->get_aes_key_bytes(), pBufIdx, m_cCrypt->get_aes_key_bytes());
		pBufIdx += m_cCrypt->get_hash_bytes();
	}

	free(pBuf);

	InitPRFKeys(keyBuf, m_nBaseOTs * m_nSndVals);

	free(keyBuf);
	chan->synchronize_end();

	delete(chan);
}

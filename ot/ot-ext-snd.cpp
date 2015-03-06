/*
 * ot-extension-sender.cpp
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */

#include "ot-ext-snd.h"

BOOL OTExtSnd::send(uint32_t numOTs, uint32_t bitlength, CBitVector& x0, CBitVector& x1, eot_flavor type, uint32_t numThreads, MaskingFunction* maskfct) {
	cout << "seclvl on send" << m_cCrypt->get_seclvl().symbits << endl;

	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_vValues[0] = x0;
	m_vValues[1] = x1;
	m_eOTFlav = type;
	m_fMaskFct = maskfct;
	return start_send(numThreads);
}

//Initialize and start numThreads OTSenderThread
BOOL OTExtSnd::start_send(uint32_t numThreads) {
	if (m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint32_t wd_size_bits = m_nBlockSizeBits;//pad_to_power_of_two(m_nBaseOTs);//1 << (ceil_log2(m_nBaseOTs));
	uint64_t numOTs = ceil_divide(PadToMultiple(m_nOTs, wd_size_bits), numThreads);

	vector<OTSenderThread*> sThreads(numThreads);

	sndthread->Start();
	rcvthread->Start();

	CEvent* rcvev= new CEvent;
	CEvent* finev = new CEvent;

	rcvthread->add_listener(OT_ADMIN_CHANNEL, rcvev, finev);

	for (uint32_t i = 0; i < numThreads; i++) {
		sThreads[i] = new OTSenderThread(i, numOTs, this);
		sThreads[i]->Start();
	}

	for (uint32_t i = 0; i < numThreads; i++) {
		sThreads[i]->Wait();
	}

	finev->Wait();

	m_nCounter += m_nOTs;

	for (uint32_t i = 0; i < numThreads; i++) {
		delete sThreads[i];
	}

#ifdef VERIFY_OT
	verifyOT(m_nOTs);
#endif
	delete rcvev;
	delete finev;
	return true;
}


void OTExtSnd::BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint32_t numblocks, uint64_t ctr) {
	BYTE* rcvbufptr = RcvBuf.GetArr();
	BYTE* Tptr = T.GetArr();
	uint8_t* ctr_buf = (uint8_t*) malloc(AES_BYTES);

	uint32_t dummy;
	uint64_t* counter = (uint64_t*) ctr_buf;
	uint32_t wd_size_bytes = m_nBlockSizeBytes;//pad_to_power_of_two(m_nBaseOTs/8);//1 << (ceil_log2(m_nBaseOTs) - 3);
	uint32_t rowbytelen = wd_size_bytes * numblocks;

	AES_KEY_CTX* seedptr = m_vBaseOTKeys;
	uint32_t otid = (*counter) - m_nCounter;

	uint32_t iters = rowbytelen / AES_BYTES;
	for (uint32_t k = 0, b; k < m_nBaseOTs; k++, rcvbufptr += rowbytelen) {
		*counter = ctr;
		for (b = 0; b < iters; b++, (*counter)++, Tptr += AES_BYTES) {
			m_cCrypt->encrypt(seedptr + k, Tptr, ctr_buf, AES_BYTES);
#ifdef DEBUG_MALICIOUS
			cout << "k = " << k << ": "<< (hex) << ((uint64_t*) Tptr)[0] << ((uint64_t*) Tptr)[1] << (hex) << endl;
#endif

		}
#ifdef DEBUG_OT_SEED_EXPANSION
		cout << "Xs[" << k << "]: " << (hex);
		for(uint64_t i = 0; i < AES_BYTES * iters; i++) {
			cout << (uint32_t) (Tptr-AES_BYTES*iters)[i];
		}
		cout << (dec) << endl;
#endif
	//	*counter = tempctr;
	}

	//XOR m_nU on top
	rcvbufptr = RcvBuf.GetArr();
	for (uint32_t k = 0; k < m_nBaseOTs; k++, rcvbufptr += rowbytelen) {
		if (m_vU.GetBit(k)) {
			T.XORBytes(rcvbufptr, k * rowbytelen, rowbytelen);
		}
	}
	free(ctr_buf);
}

void OTExtSnd::HashValues(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint64_t ctr, uint64_t processedOTs) {
	uint64_t numhashiters = ceil_divide(m_nBitLength, m_cCrypt->get_hash_bytes());
	uint32_t rowbytelen = bits_in_bytes(m_nBaseOTs);
	uint32_t hashinbytelen = rowbytelen + sizeof(uint64_t);
	uint64_t wd_size_bytes = m_nBlockSizeBytes;//1 << (ceil_log2(m_nBaseOTs) - 3);
	uint32_t u;
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	uint8_t* resbuf= (uint8_t*) malloc(m_cCrypt->get_hash_bytes());
	uint8_t* inbuf= (uint8_t*) malloc(hashinbytelen);

	uint64_t* Qptr = (uint64_t*) Q.GetArr();
	uint64_t* Uptr = (uint64_t*) m_vU.GetArr();

	uint8_t** sbp = (uint8_t**) malloc(sizeof(uint8_t*) * m_nSndVals);

	for (u = 0; u < m_nSndVals; u++)
		sbp[u] = seedbuf[u].GetArr();

	for (uint64_t i = ctr, j = 0; j < processedOTs; i++, j++, Qptr += 2) {

#ifndef FIXED_KEY_AES_HASHING
		/*MPC_HASH_INIT(&sha);
		MPC_HASH_UPDATE(&sha, (BYTE*) &i, sizeof(i));

		shatmp = sha;*/
#endif
		for (u = 0; u < m_nSndVals; u++) {

#ifdef HIGH_SPEED_ROT_LT
			if(u == 1) {
				Qptr[0]^=Uptr[0];
				Qptr[1]^=Uptr[1];
			}
#else
			if (u == 1)
				Q.XORBytes((uint8_t*) Uptr, j * wd_size_bytes, rowbytelen);
#endif

#ifdef DEBUG_OT_HASH
			cout << "Hash-In for i = " << i << ", u = " << u << ": " << (hex);
			for(uint32_t p = 0; p < rowbytelen; p++)
				cout << (uint32_t) (Q.GetArr() + j * wd_size_bytes)[p];
			cout << (dec) << endl;
#endif

#ifdef FIXED_KEY_AES_HASHING
			FixedKeyHashing(m_kCRFKey, sbp[u], (BYTE*) Qptr, hash_buf, i, hashinbytelen, m_cCrypt);
#else
			//sha = shatmp;
			//m_cCrypt->hash_ctr(sbp[u], AES_KEY_BYTES, Q.GetArr() + j * wd_size_bytes, hashinbytelen, i);
			memcpy(inbuf, &i, sizeof(uint64_t));
			memcpy(inbuf+sizeof(uint64_t), Q.GetArr() + j * wd_size_bytes, rowbytelen);
			m_cCrypt->hash(resbuf, aes_key_bytes, inbuf, hashinbytelen);
			//m_cCrypt->hash_ctr(sbp[u], aes_key_bytes, Q.GetArr() + j * wd_size_bytes,  rowbytelen, i);
			memcpy(sbp[u], resbuf, aes_key_bytes);
			//MPC_HASH_UPDATE(&sha, Q.GetArr()+ j * wd_size_bytes, hashinbytelen);
			//MPC_HASH_FINAL(&sha, hash_buf);

			//memcpy(sbp[u], hash_buf, AES_KEY_BYTES);
#endif
			sbp[u] += aes_key_bytes;
		}
	}

#ifndef HIGH_SPEED_ROT_LT
	//Two calls to expandMask, both writing into snd_buf
	for (uint32_t u = 0; u < m_nSndVals; u++)
		m_fMaskFct->expandMask(snd_buf[u], seedbuf[u].GetArr(), 0, processedOTs, m_nBitLength, m_cCrypt);
#endif

	free(resbuf);
	free(inbuf);
	free(sbp);
}

void OTExtSnd::MaskAndSend(CBitVector* snd_buf, uint32_t id, uint32_t progress, uint32_t processedOTs) {
	m_fMaskFct->Mask(progress, processedOTs, m_vValues, snd_buf, m_eOTFlav);

	if (m_eOTFlav == R_OT)
		return;

	uint64_t bufsize = bits_in_bytes(processedOTs * m_nBitLength);
	uint8_t* buf;
	if (m_eOTFlav == OT) {
		buf = (uint8_t*) malloc(2*bufsize);
		memcpy(buf, snd_buf[0].GetArr(), bufsize);
		memcpy(buf+ bufsize, snd_buf[1].GetArr(), bufsize);
		bufsize *= 2;
	} else if (m_eOTFlav == C_OT) {
		buf = (uint8_t*) malloc(bufsize);
		memcpy(buf, snd_buf[1].GetArr(), bufsize);
	}

	sndthread->add_snd_task_start_len(id, bufsize, buf, progress, processedOTs);
	free(buf);
	/*OTBlock* block = new OTBlock;
	uint32_t bufsize = ceil_divide(processedOTs * m_nBitLength, 8);

	block->blockid = progress;
	block->processedOTs = processedOTs;

	if (m_eOTFlav == G_OT) {
		block->snd_buf = new BYTE[bufsize << 1];
		memcpy(block->snd_buf, snd_buf[0].GetArr(), bufsize);
		memcpy(block->snd_buf + bufsize, snd_buf[1].GetArr(), bufsize);
	} else if (m_eOTFlav == C_OT) {
		block->snd_buf = new BYTE[bufsize];
		memcpy(block->snd_buf, snd_buf[1].GetArr(), bufsize);
	}

	m_lSendLock->Lock();
	//Lock this part if multiple threads are used!
	if (m_nBlocks == 0) {
		m_sBlockHead = block;
		m_sBlockTail = block;
	} else {
		m_sBlockTail->next = block;
		m_sBlockTail = block;
	}
	m_nBlocks++;
	m_lSendLock->Unlock();*/
}

/*void OTExtSnd::SendBlocks(uint32_t numThreads) {
	OTBlock* tempBlock;
	uint32_t progress = 0;
	uint32_t csockid = 0;
	if (m_eOTFlav == R_OT)
		return;

#ifdef OTTiming
	double totalTnsTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (progress < m_nOTs) {

		if (m_nBlocks > 0) {
#ifdef OTTiming
			gettimeofday(&tempStart, NULL);
#endif
			tempBlock = m_sBlockHead;

			//send: blockid, #processedOTs, threadid, #checks, permbits
			m_vSockets[csockid].Send((BYTE*) &(tempBlock->blockid), sizeof(uint32_t));
			m_vSockets[csockid].Send((BYTE*) &(tempBlock->processedOTs), sizeof(uint32_t));

			if (m_eOTFlav == G_OT) {
				m_vSockets[csockid].Send(tempBlock->snd_buf, 2 * ceil_divide((tempBlock->processedOTs) * m_nBitLength, 8));
			} else if (m_eOTFlav == C_OT) {
				m_vSockets[csockid].Send(tempBlock->snd_buf, ceil_divide((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			//Lock this part
			m_sBlockHead = m_sBlockHead->next;

			m_lSendLock->Lock();
			m_nBlocks--;
			m_lSendLock->Unlock();

			progress += tempBlock->processedOTs;
			if (m_eOTFlav != R_OT)
				delete tempBlock->snd_buf;

			delete tempBlock;

#ifdef OTTiming
			gettimeofday(&tempEnd, NULL);
			totalTnsTime += getMillies(tempStart, tempEnd);
#endif
		}
	}
#ifdef OTTiming
	cout << "Total time spent transmitting data: " << totalTnsTime << endl;
#endif
}*/

BOOL OTExtSnd::verifyOT(uint64_t NumOTs) {
	cout << "Verifying OT" << endl;
	uint64_t processedOTBlocks, OTsPerIteration;
	uint32_t bytelen = ceil_divide(m_nBitLength, 8);
	uint64_t nSnd;
	uint8_t resp;

	CEvent* rcvev= new CEvent;
	CEvent* finev = new CEvent;
	queue<uint8_t*>* rcvqueue = rcvthread->add_listener(0, rcvev, finev);

	for (uint64_t i = 0; i < NumOTs; i += OTsPerIteration) {
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(NumOTs - i, AES_BITS));
		OTsPerIteration = min(processedOTBlocks * AES_BITS, NumOTs - i);
		nSnd = ceil_divide(OTsPerIteration * m_nBitLength, 8);

		sndthread->add_snd_task_start_len(0, nSnd, m_vValues[0].GetArr() + bits_in_bytes(i * m_nBitLength), i, OTsPerIteration);
		sndthread->add_snd_task_start_len(0, nSnd, m_vValues[1].GetArr() + bits_in_bytes(i * m_nBitLength), i, OTsPerIteration);

		cout << "Waiting for reply" << endl;
		rcvev->Wait();
		resp = *rcvqueue->front();
		rcvqueue->pop();
		cout << "Got reply with " << (uint32_t) resp << endl;
		if (resp == 0x00) {
			cout << "OT verification unsuccessful" << endl;
			return false;
		}
	}
	cout << "signalling end" << endl,
	sndthread->signal_end(0);
	cout << "OT Verification successful" << flush << endl;

	delete rcvev;
	delete finev;

	return true;
}

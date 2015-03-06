/*
 * iknp-ot-ext-sender.cpp
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */

#include "iknp-ot-ext-snd.h"

//BOOL OTsender(int nSndVals, int nOTs, int startpos, CSocket& sock, CBitVector& U, AES_KEY* vKeySeeds, CBitVector* values, BYTE* seed)
BOOL IKNPOTExtSnd::sender_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t nProgress;
	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;//1 << (ceil_log2(m_nBaseOTs));
	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + myNumOTs;

	// The vector with the received bits
	CBitVector vRcv(m_nBaseOTs * OTsPerIteration);

	// Holds the reply that is sent back to the receiver
	uint32_t numsndvals = 2;
	CBitVector* vSnd;

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration * m_cCrypt->get_aes_key_bytes() * 8);
#ifdef ZDEBUG
	cout << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << endl;
#endif
	vSnd = new CBitVector[numsndvals];	//(CBitVector*) malloc(sizeof(CBitVector) * numsndvals);
	for (uint32_t i = 0; i < numsndvals; i++) {
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Contains the parts of the V matrix
	CBitVector Q(wd_size_bits * OTsPerIteration);

	uint64_t counter = myStartPos + m_nCounter;

	nProgress = myStartPos;

	CEvent* rcvev = new CEvent();
	CEvent* finev = new CEvent();
	queue<uint8_t*>* rcvqueue;
	uint8_t *rcvbuftmpptr, *rcvbufptr;
	cout << "Registering on channel" << endl;
	rcvqueue = rcvthread->add_listener(id, rcvev, finev);
	//rcvthread->Start();

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (nProgress < lim && finev->Set()) //do while there are still transfers missing
	{
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - nProgress, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;

#ifdef ZDEBUG
		cout << "Processing block " << nProgress << " with length: " << OTsPerIteration << ", and limit: " << lim << endl;
#endif

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		if(rcvqueue->empty())
			rcvev->Wait();
		rcvbufptr = rcvqueue->front();
		rcvqueue->pop();
		rcvbuftmpptr = rcvbufptr;
		uint64_t tmpctr = *((uint64_t*) rcvbuftmpptr);
		rcvbuftmpptr+=sizeof(uint64_t);
		uint64_t tmpotlen = *((uint64_t*) rcvbuftmpptr);
		rcvbuftmpptr+=sizeof(uint64_t);
		vRcv.AttachBuf(rcvbuftmpptr, bits_in_bytes(m_nBaseOTs * OTsPerIteration));
		cout << "I am processing OTs from " << tmpctr << " with len = " << tmpotlen << endl;

		//sock->Receive(vRcv.GetArr(), ceil_divide(m_nBaseOTs * OTsPerIteration, 8));
		//TODO
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		BuildQMatrix(Q, vRcv, processedOTBlocks, counter);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		Q.EklundhBitTranspose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		HashValues(Q, seedbuf, vSnd, nProgress, min(lim - nProgress, OTsPerIteration));
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		MaskAndSend(vSnd, id, nProgress, min(lim - nProgress, OTsPerIteration));
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		counter += min(lim - nProgress, OTsPerIteration);
		nProgress += min(lim - nProgress, OTsPerIteration);
		Q.Reset();
		free(rcvbufptr);
	}

	sndthread->signal_end(id);
	//vRcv.delCBitVector();
	Q.delCBitVector();
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].delCBitVector();

	for (uint32_t i = 0; i < numsndvals; i++)
		vSnd[i].delCBitVector();
	if (numsndvals > 0)
		free(vSnd);


#ifdef OTTiming
	cout << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

#ifndef BATCH
	cout << "Sender finished successfully" << endl;
#endif
	return TRUE;
}

/*
 * iknp-ot-ext-receiver.cpp
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */

#include "iknp-ot-ext-rec.h"


BOOL IKNPOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t myStartPos = id * myNumOTs;
	uint64_t i = myStartPos, nProgress = myStartPos;
	uint32_t RoundWindow = 2;
	uint32_t roundctr = 0;
	uint64_t wd_size_bits = m_nBlockSizeBits;//1 << (ceil_log2(m_nBaseOTs));

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + myNumOTs;

	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t OTwindow = NUMOTBLOCKS * wd_size_bits * RoundWindow;
	//CSocket* sock = m_vSockets+id;

	//counter variables
	uint64_t numblocks = ceil_divide(myNumOTs, OTsPerIteration);
	uint64_t nSize;

	// The receive buffer
	//CBitVector vRcv;
	//if (m_eOTFlav == OT)
	//	vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	//else if (m_eOTFlav == C_OT)	// || m_eOTFlav == S_OT)
	//	vRcv.Create(OTsPerIteration * m_nBitLength);

	cout << "windowsize = " << wd_size_bits << ", ots per iter: " << OTsPerIteration << endl;
	// A temporary part of the T matrix
	CBitVector T(wd_size_bits * OTsPerIteration);

	// The send buffer
	CBitVector vSnd(m_nBaseOTs * OTsPerIteration);

	// A temporary buffer that stores the resulting seeds from the hash buffer
	//TODO: Check for some maximum size
	CBitVector seedbuf(OTwindow * m_cCrypt->get_aes_key_bytes() * 8);

	uint64_t counter = myStartPos + m_nCounter;


	CEvent* notifyrcv = new CEvent;
	CEvent* finevent = new CEvent;
	//Register new receiving thread

	queue<uint8_t*>* rcv_buf = rcvthread->add_listener(id, notifyrcv, finevent);
	//rcvthread->Start();
#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalChkTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (i < lim) {
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - i, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, vSnd, processedOTBlocks, i);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		cout << "transposing T as a " << wd_size_bits << " x " << OTsPerIteration << " matrix" << endl;

		T.EklundhBitTranspose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		HashValues(T, seedbuf, i, min(lim - i, OTsPerIteration));
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		sndthread->add_snd_task_start_len(id, nSize, vSnd.GetArr(), i, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif

		if(!rcv_buf->empty()) {
			ReceiveAndUnMask(rcv_buf);
		}

		counter += min(lim - i, OTsPerIteration);
		i += min(lim - i, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
#endif

		vSnd.Reset();
		T.Reset();
	}
	sndthread->signal_end(id);

	if(m_eOTFlav != R_OT) {
		finevent->Wait();
		ReceiveAndUnMask(rcv_buf);
	}

	T.delCBitVector();
	vSnd.delCBitVector();
	seedbuf.delCBitVector();

#ifdef OTTiming
	cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif
#ifndef BATCH
	cout << "Receiver finished successfully" << endl;
#endif
	//sleep(1);
	return TRUE;
}

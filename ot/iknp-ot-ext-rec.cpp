/*
 * iknp-ot-ext-receiver.cpp
 *
 *  Created on: Mar 4, 2015
 *      Author: mzohner
 */

#include "iknp-ot-ext-rec.h"


BOOL IKNPOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + myNumOTs;

	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t OTwindow = NUMOTBLOCKS * wd_size_bits;
	uint64_t** rndmat;
	channel* chan = new channel(OT_BASE_CHANNEL+id, m_cRcvThread, m_cSndThread);

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

	queue<mask_block*> mask_queue;

	CBitVector maskbuf;
	maskbuf.Create(m_nBitLength * OTwindow);

	if(m_eSndOTFlav == Snd_GC_OT) {
		uint8_t* rnd_seed = chan->blocking_receive();
		initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
		fillRndMatrix(rnd_seed, rndmat, m_nBitLength, m_nBaseOTs, m_cCrypt);
		free(rnd_seed);
	}

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalChkTime = 0, totalMaskTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (otid < lim) {
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		//nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

#ifdef ZDEBUG
		cout << "Receiver thread " << id << " processing block " << otid <<
				" with length: " << OTsPerIteration << ", and limit: " << lim << endl;
#endif


#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, vSnd, otid, processedOTBlocks, m_tBaseOTKeys.front());
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
		HashValues(&T, &seedbuf, &maskbuf, otid, min(lim - otid, OTsPerIteration), rndmat);
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
		SetOutput(&maskbuf, otid, OTsPerIteration, &mask_queue, chan);//ReceiveAndUnMask(chan);

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

	if(m_eSndOTFlav != Snd_R_OT && m_eSndOTFlav != Snd_GC_OT) {
		//finevent->Wait();
#ifdef ABY_OT
		while(!(mask_queue.empty())) {
#else
		while(chan->is_alive() && !(mask_queue.empty())) {
#endif
			ReceiveAndUnMask(chan, &mask_queue);
		}
	}

#ifdef ZDEBUG
	cout << "Receiver thread " << id << " finished " << endl;
#endif


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


void IKNPOTExtRec::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	delete m_cBaseOT;
}

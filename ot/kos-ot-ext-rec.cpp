#include "kos-ot-ext-rec.h"


BOOL KOSOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	// differences to IKNP:
	// In the beginning we receive a random seed for the weights from the sender
	// The main loop has to be split into two loops. In the first loop, the matrices T and vSnd are built completely.
	// the second loop deals with Hashing the rows in T and receive+unmask the actual values.
	// In between the loops some additional OTs must be handled and the checksums
	// (calculated in the first loop, as well as for the additional OTs) must be sent to the sender.
	// The second loop can only make any real progress, if the sender accepts the checksums and continues the protocol.
	// Due to this split we need to store all the instances of T built in the first loop, so we can use them in the second.
	// IMPORTANT: Currently each thread is totally independant from the others. That means, each thread will also
	// perform the additional OTs!

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

	// stores all instances of T
	vector<CBitVector*> T_list;
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

	// receive seed for weights from server and init random state
	uint8_t *weights_seed = chan->blocking_receive();
	prf_state_ctx weights_prf_state;
	m_cCrypt->init_prf_state(&weights_prf_state, weights_seed);
	free(weights_seed);

	uint64_t weightLength = bits_in_bytes(m_nBaseOTs);
	// multiplication is used for tCheck, so its size is twice the size of the weights
	// for xCheck, no multiplication is used. weights are only added to it.
	uint8_t *tCheck = (uint8_t *)calloc(2 * weightLength, 1);
	uint8_t *xCheck = (uint8_t *)calloc(weightLength, 1);


#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalChkTime = 0, totalMaskTime = 0;
	timeval tempStart, tempEnd;
#endif

	// first loop - build matrices, send vSnd, transpose T and calculate checksum.
	while (otid < lim) {
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		//nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

		// A temporary part of the T matrix
		CBitVector *T = new CBitVector(wd_size_bits * OTsPerIteration);

#ifdef ZDEBUG
		cout << "Receiver thread " << id << " processing block " << otid <<
				" with length: " << OTsPerIteration << ", and limit: " << lim << endl;
#endif


#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, &vSnd, otid, processedOTBlocks, m_tBaseOTKeys.front());
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		MaskBaseOTs(T, &vSnd, otid, processedOTBlocks);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMaskTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		T->Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		SendMasks(&vSnd, chan, otid, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif

		calculateChecksum(T, &weights_prf_state, m_vChoices, otid, tCheck, xCheck, min(lim - otid, OTsPerIteration));

		T_list.push_back(T);
		vSnd.Reset();

		otid += min(lim - otid, OTsPerIteration);
	}

	handleAdditionalOTs(chan, &weights_prf_state, tCheck, xCheck, myStartPos);

	// send checksums to sender
	chan->send(tCheck, 2 * weightLength);
	chan->send(xCheck, weightLength);

	// second loop - hash T rows, receive and unmask values
	otid = myStartPos;
	for (size_t i = 0; i < T_list.size(); i++) {
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		//nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

		CBitVector *T = T_list[i];

		HashValues(T, &seedbuf, &maskbuf, otid, min(lim - otid, OTsPerIteration), rndmat);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		SetOutput(&maskbuf, otid, OTsPerIteration, &mask_queue, chan);//ReceiveAndUnMask(chan);

		//counter += min(lim - OT_ptr, OTsPerIteration);
		otid += min(lim - otid, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
#endif
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

	free(tCheck);
	free(xCheck);
	m_cCrypt->free_prf_state(&weights_prf_state);
	for (size_t i = 0; i < T_list.size(); i++) {
		delete T_list[i];
	}
	seedbuf.delCBitVector();
	maskbuf.delCBitVector();
	delete chan;

	return TRUE;
}


void KOSOTExtRec::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	delete m_cBaseOT;
}

void KOSOTExtRec::calculateChecksum(CBitVector* T,
		prf_state_ctx* weights_prf_state, CBitVector* choices,
		uint64_t choicesOffset, uint8_t* tCheck, uint8_t* xCheck,
		uint64_t numOTs) {

	// length of weights and rows in T (might be different!)
	uint64_t weightLength = bits_in_bytes(m_nBaseOTs);
	uint64_t wd_size_bytes = m_nBlockSizeBytes;

	// generate random weight for each OT
	uint8_t *weights = (uint8_t *)malloc(weightLength * numOTs);
	gen_rnd_bytes(weights_prf_state, weights, weightLength * numOTs);

	uint8_t *weight_ptr = weights;
	uint8_t *T_ptr = T->GetArr();

	// for each OT add (row-in-T * weight) to tCheck
	// and x * weight to xCheck, where x is the choice bit
	for (uint64_t i = 0; i < numOTs; i++) {
		carrylessMultiplication(T_ptr, weight_ptr, tCheck, weightLength);

		if (choices->GetBitNoMask(i + choicesOffset)) {
			for (uint64_t k = 0; k < weightLength; k++) {
				xCheck[k] ^= weight_ptr[k];
			}
		}

		weight_ptr += weightLength;
		T_ptr += wd_size_bytes;
	}

	free(weights);
}

void KOSOTExtRec::handleAdditionalOTs(channel* chan,
		prf_state_ctx* weights_prf_state, uint8_t* tCheck, uint8_t* xCheck,
		uint64_t firstOTid) {
	uint64_t wd_size_bits = m_nBlockSizeBits;
	uint64_t additionalOTBlocks = ceil_divide(m_nAdditionalOTs, wd_size_bits);
	uint64_t OTsInMatrix = additionalOTBlocks * wd_size_bits;

	// use huge offset to give additional OTs ids that will not be taken by any future OTs
	uint64_t additionalID = firstOTid + 0x7700000000000000;

	CBitVector additionalChoices(m_nAdditionalOTs, m_cCrypt);

	CBitVector T(wd_size_bits * OTsInMatrix);

#ifdef GENERATE_T_EXPLICITELY
	CBitVector vSnd(m_nBaseOTs * OTsInMatrix * 2);
#else
	CBitVector vSnd(m_nBaseOTs * OTsInMatrix);
#endif

	BuildMatrices(&T, &vSnd, additionalID, additionalOTBlocks, m_tBaseOTKeys.front());
	AdditionalMaskBaseOTs(&T, &vSnd, &additionalChoices, additionalOTBlocks);
	T.Transpose(wd_size_bits, OTsInMatrix);
	SendMasks(&vSnd, chan, additionalID, OTsInMatrix);

	calculateChecksum(&T, weights_prf_state, &additionalChoices, 0, tCheck, xCheck, m_nAdditionalOTs);
}

void KOSOTExtRec::AdditionalMaskBaseOTs(CBitVector* T, CBitVector* SndBuf,
		CBitVector* choices, uint64_t numblocks) {
	// This function is necessary because MaskBaseOTs only works on m_vChoices. Other than that
	// it is identical to MaskBaseOTs. In fact, except for the first couple lines, it is an exact copy
	// of MaskBaseOTs. So if anything in MaskBaseOTs changes, those changes can just be copied to here.
	// I even created a local variable named m_vChoices so that the rest of the code didn't require any changes at all!


	uint64_t rowbytelen = m_nBlockSizeBytes * numblocks;
	uint64_t choicebytelen = bits_in_bytes(m_nAdditionalOTs);
	// we always start at the beginning of our custom choice vector
	uint32_t OTid = 0;
	// rename choices to m_vChoices to avoid changes in the rest of the code
	CBitVector *m_vChoices = choices;
	uint8_t* choiceptr;// = m_nChoices.GetArr() + ceil_divide(OTid, 8);
	CBitVector tmp;


#ifdef GENERATE_T_EXPLICITELY
	//Some nasty moving to compress the code, this part is only required for benchmarking
	uint32_t blockbytesize = rowbytelen * m_nBaseOTs;
	if(m_eRecOTFlav == Rec_R_OT) {
		tmp.CreateBytes(rowbytelen);
		tmp.Reset();
		tmp.XORBytesReverse(SndBuf->GetArr(), 0, rowbytelen);
		tmp.XORBytesReverse(T->GetArr(), 0, rowbytelen);
		m_vChoices->Copy(tmp.GetArr(), ceil_divide(OTid, 8), choicebytelen);

		SndBuf->SetBytes(SndBuf->GetArr()+rowbytelen, blockbytesize-rowbytelen, blockbytesize-rowbytelen);
		SndBuf->SetBytes(T->GetArr()+rowbytelen, 0, blockbytesize-rowbytelen);
		T->FillRand(blockbytesize << 3, m_cCrypt);
		T->SetBytesToZero(0, rowbytelen);
		SndBuf->XORBytes(T->GetArr()+rowbytelen, 0, blockbytesize-rowbytelen);
		SndBuf->XORBytes(T->GetArr()+rowbytelen, blockbytesize-rowbytelen, blockbytesize-rowbytelen);

		for (uint32_t k = 0; k < m_nBaseOTs-1; k++) {
			SndBuf->XORBytesReverse(m_vChoices->GetArr() + ceil_divide(OTid, 8), blockbytesize +  k * rowbytelen, choicebytelen);
		}
	} else {
		uint32_t blockbytesize = rowbytelen * m_nBaseOTs;
		SndBuf->SetBytes(SndBuf->GetArr(), blockbytesize, blockbytesize);
		SndBuf->SetBytes(T->GetArr(), 0, blockbytesize);
		T->FillRand(blockbytesize << 3, m_cCrypt);
		SndBuf->XORBytes(T->GetArr(), 0, blockbytesize);
		SndBuf->XORBytes(T->GetArr(), blockbytesize, blockbytesize);

		for (uint32_t k = 0; k < m_nBaseOTs; k++) {
			SndBuf->XORBytesReverse(m_vChoices->GetArr() + ceil_divide(OTid, 8), blockbytesize +  k * rowbytelen, choicebytelen);
		}
	}

#else
	tmp.CreateBytes(rowbytelen);
	tmp.Reset();

	if(m_eRecOTFlav == Rec_R_OT) {
		tmp.XORBytesReverse(SndBuf->GetArr(), 0, rowbytelen);
		tmp.XORBytesReverse(T->GetArr(), 0, rowbytelen);

		m_vChoices->Copy(tmp.GetArr(), ceil_divide(OTid, 8), choicebytelen);
	} else {
		tmp.Copy(m_vChoices->GetArr() + ceil_divide(OTid, 8), 0, choicebytelen);
	}
	choiceptr = tmp.GetArr();
	for (uint32_t k = 0; k < m_nBaseOTs; k++) {
		SndBuf->XORBytesReverse(choiceptr, k * rowbytelen, rowbytelen);
	}

	SndBuf->XORBytes(T->GetArr(), 0, rowbytelen * m_nBaseOTs);
	tmp.delCBitVector();
#endif
	//cout << "SB: ";
	//SndBuf.PrintHex(0, 32);
}






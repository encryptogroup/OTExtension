#include "kos-ot-ext-snd.h"
#include "carryless-multiplication.h"

//BOOL OTsender(int nSndVals, int nOTs, int startpos, CSocket& sock, CBitVector& U, AES_KEY* vKeySeeds, CBitVector* values, BYTE* seed)
BOOL KOSOTExtSnd::sender_routine(uint32_t id, uint64_t myNumOTs) {
	// differences to IKNP:
	// In the beginning we generate a random seed for the weights and send it to the receiver
	// The main loop has to be split into two loops. In the first loop, the matrix Q is built completely.
	// the second loop deals with Hashing the rows in Q and mask+send the actual values.
	// In between the loops some additional OTs must be handled and the checksums
	// (calculated in the first loop, as well as for the additional OTs) must be checked.
	// Only if it is correct, the second loop starts.
	// Due to this split we need to store all the instances of Q built in the first loop, so we can use them in the second.
	// IMPORTANT: Currently each thread is totally independant from the others. That means, each thread will also
	// perform the additional OTs! You could make it so that only one thread performs them, but then you have to
	// stop all threads from entering the second loop until the checksums of all threads have been accumulated and checked.


	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;
	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	channel* chan = new channel(OT_BASE_CHANNEL+id, m_cRcvThread, m_cSndThread);
	uint64_t tmpctr, tmpotlen;
	uint64_t** rndmat;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + myNumOTs;

	// The vector with the received bits
#ifdef GENERATE_T_EXPLICITELY
	CBitVector vRcv(2 * m_nBaseOTs * OTsPerIteration);
#else
	CBitVector vRcv(m_nBaseOTs * OTsPerIteration);
#endif

	// Holds the reply that is sent back to the receiver
	uint32_t numsndvals = 2;
	CBitVector* vSnd;

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration * m_cCrypt->get_aes_key_bytes() * 8);
#ifdef ZDEBUG
	cout << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << endl;
#endif
	vSnd = new CBitVector[numsndvals];
	for (uint32_t i = 0; i < numsndvals; i++) {
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Q Contains the parts of the V matrix
	// But instead of one Q, we need a list of Qs.
	vector<CBitVector*> Q_list;

	uint64_t otid = myStartPos;

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

	// generate and send seed for the weights used in the checksum
	uint8_t *weights_seed = (uint8_t*)malloc(m_nSymSecParam);
	m_cCrypt->gen_rnd(weights_seed, m_nSymSecParam);
	chan->send(weights_seed, m_nSymSecParam);
	prf_state_ctx weights_prf_state;
	m_cCrypt->init_prf_state(&weights_prf_state, weights_seed);
	free(weights_seed);

	uint64_t weightLength = bits_in_bytes(m_nBaseOTs);
	// since we don't reduce after multiplication, the checksum is twice as long as the weights
	// this was also done by the authors of KOS15.
	uint8_t *qCheck = (uint8_t *)calloc(2 * weightLength, 1);


	// first loop - build Q matrices, transpose them and calculate checksum.
	while (otid < lim) //do while there are still transfers missing
	{
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;

		CBitVector *Q = new CBitVector(wd_size_bits * OTsPerIteration);


#ifdef ZDEBUG
		cout << "Sender thread " << id << " processing block " << otid <<
				" with length: " << OTsPerIteration << ", and limit: " << lim << endl;
#endif

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		ReceiveMasks(&vRcv, chan, OTsPerIteration);

#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		BuildQMatrix(Q, otid, processedOTBlocks, m_tBaseOTKeys.front());
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		UnMaskBaseOTs(Q, &vRcv, m_tBaseOTChoices.front(), processedOTBlocks);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalUnMaskTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		Q->Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif

		calculateChecksum(Q, &weights_prf_state, qCheck, min(lim - otid, OTsPerIteration));

		Q_list.push_back(Q);
		otid += min(lim - otid, OTsPerIteration);
	}

	handleAdditionalOTs(chan, &weights_prf_state, qCheck, myStartPos);

	if (!controlChecksum(qCheck, chan)) {
		cout << "KOS: invalid checksum." << endl;
		exit(-1);
	}

	// second loop - hash Q rows, mask and send values
	otid = myStartPos;
	for (size_t i = 0; i < Q_list.size(); i++) {

		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;

		CBitVector *Q = Q_list[i];

		HashValues(Q, seedbuf, vSnd, m_tBaseOTChoices.front(), otid, min(lim - otid, OTsPerIteration), rndmat);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		MaskAndSend(vSnd, otid, min(lim - otid, OTsPerIteration), chan);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		otid += min(lim - otid, OTsPerIteration);
	}

#ifdef ZDEBUG
	cout << "Sender thread " << id << " finished " << endl;
#endif

	free(qCheck);
	m_cCrypt->free_prf_state(&weights_prf_state);

	vRcv.delCBitVector();
	chan->synchronize_end();

	for (size_t i = 0; i < Q_list.size(); i++) {
		delete Q_list[i];
	}
	delete[] seedbuf;
	delete[] vSnd;

	if(m_eSndOTFlav==Snd_GC_OT)
		freeRndMatrix(rndmat, m_nBaseOTs);

#ifdef OTTiming
	cout << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
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


void KOSOTExtSnd::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	delete m_cBaseOT;
}

void KOSOTExtSnd::calculateChecksum(CBitVector* Q,
		prf_state_ctx* weights_prf_state, uint8_t* qCheck, uint64_t numOTs) {
	// length of weights and rows in Q (might be different!)
	uint64_t weightLength = bits_in_bytes(m_nBaseOTs);
	uint64_t wd_size_bytes = m_nBlockSizeBytes;

	// generate random weight for each OT
	uint8_t *weights = (uint8_t *)malloc(weightLength * numOTs);
	gen_rnd_bytes(weights_prf_state, weights, weightLength * numOTs);

	uint8_t *weight_ptr = weights;
	uint8_t *Q_ptr = Q->GetArr();

	// for each OT add (row-in-Q * weight) to the checksum
	for (uint64_t i = 0; i < numOTs; i++) {
		carrylessMultiplication(Q_ptr, weight_ptr, qCheck, weightLength);
		weight_ptr += weightLength;
		Q_ptr += wd_size_bytes;
	}

	free(weights);
}

void KOSOTExtSnd::handleAdditionalOTs(channel* chan, prf_state_ctx* weights_prf_state, uint8_t* qCheck, uint64_t firstOTid) {
	uint64_t wd_size_bits = m_nBlockSizeBits;
	uint64_t additionalOTBlocks = ceil_divide(m_nAdditionalOTs, wd_size_bits);
	uint64_t OTsInMatrix = additionalOTBlocks * wd_size_bits;

	// use huge offset to give additional OTs ids that will not be taken by any future OTs
	uint64_t additionalID = firstOTid + 0x7700000000000000;

#ifdef GENERATE_T_EXPLICITELY
	CBitVector vRcv(2 * m_nBaseOTs * OTsInMatrix);
#else
	CBitVector vRcv(m_nBaseOTs * OTsInMatrix);
#endif

	CBitVector Q(wd_size_bits * OTsInMatrix);

	ReceiveMasks(&vRcv, chan, OTsInMatrix);
	BuildQMatrix(&Q, additionalID, additionalOTBlocks, m_tBaseOTKeys.front());
	UnMaskBaseOTs(&Q, &vRcv, m_tBaseOTChoices.front(), additionalOTBlocks);
	Q.Transpose(wd_size_bits, OTsInMatrix);

	calculateChecksum(&Q, weights_prf_state, qCheck, m_nAdditionalOTs);
}

bool KOSOTExtSnd::controlChecksum(uint8_t* qCheck, channel* chan) {
	uint64_t weightLength = bits_in_bytes(m_nBaseOTs);
	uint8_t *tCheck = chan->blocking_receive();
	uint8_t *xCheck = chan->blocking_receive();

	// server secret (named DELTA in KOS15)
	uint8_t *U_ptr = m_tBaseOTChoices.front()->GetArr();

	// in the terms of kOS15: calculate t += x * DELTA and then check, if t equals q
	carrylessMultiplication(xCheck, U_ptr, tCheck, weightLength);
	bool checkOK = memcmp(qCheck, tCheck, 2 * weightLength) == 0;

	free(tCheck);
	free(xCheck);

	return checkOK;
}





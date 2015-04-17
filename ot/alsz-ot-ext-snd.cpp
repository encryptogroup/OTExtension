/*
 * alsz-ot-ext-snd.cpp
 *
 *  Created on: Mar 23, 2015
 *      Author: mzohner
 */


#include "alsz-ot-ext-snd.h"

BOOL ALSZOTExtSnd::sender_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;
	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t tmpctr, tmpotlen;
	uint32_t nchans = 2;
	bool use_mat_chan = (m_eSndOTFlav == Snd_GC_OT || m_bUseMinEntCorRob);
	if(use_mat_chan) {
		nchans = 3;
	}

	channel* ot_chan = new channel(nchans*id, m_cRcvThread, m_cSndThread);
	channel* check_chan = new channel(nchans*id + 1, m_cRcvThread, m_cSndThread);
	channel* mat_chan;
	if(use_mat_chan) {
		mat_chan = new channel(nchans*id+2, m_cRcvThread, m_cSndThread);
	}

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + myNumOTs;
	uint64_t** rndmat;

	// The vector with the received bits
	CBitVector vRcv(m_nBaseOTs * OTsPerIteration);
	vRcv.Reset();

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

	// Contains the parts of the V matrix
	CBitVector Q(wd_size_bits * OTsPerIteration);
	mask_buf_t tmpmaskbuf;

	uint64_t OT_ptr = myStartPos;

	uint8_t *rcvbuftmpptr, *rcvbufptr;

	queue<snd_check_t> check_queue;
	queue<mask_buf_t> mask_queue;

	uint32_t startpos = 0;
	if(m_eRecOTFlav==Rec_R_OT) {
		startpos = 1;
	}

	if(m_eSndOTFlav == Snd_GC_OT) {
		initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
	}

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalUnMaskTime = 0,
			totalHashCheckTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (OT_ptr < lim) //do while there are still transfers missing
	{
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - OT_ptr, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;

#ifdef ZDEBUG
		cout << "Processing block " << nProgress << " with length: " << OTsPerIteration << ", and limit: " << lim << endl;
#endif

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		rcvbufptr = ot_chan->blocking_receive_id_len(&rcvbuftmpptr, &tmpctr, &tmpotlen);
		//vRcv.AttachBuf(rcvbuftmpptr, bits_in_bytes(m_nBaseOTs * OTsPerIteration));
		vRcv.SetBytes(rcvbuftmpptr, bits_in_bytes(OTsPerIteration*startpos), bits_in_bytes((m_nBaseOTs-startpos)*OTsPerIteration));
		free(rcvbufptr);
		//vRcv.PrintHex();
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		BuildQMatrix(Q, OT_ptr, processedOTBlocks);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		check_queue.push(UpdateCheckBuf(Q.GetArr(), vRcv.GetArr(), OT_ptr, processedOTBlocks, check_chan));
		//TODO
		FillAndSendRandomMatrix(rndmat, mat_chan);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHashCheckTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		UnMaskBaseOTs(Q, vRcv, processedOTBlocks);

		GenerateSendAndXORCorRobVector(Q, OTsPerIteration, mat_chan);

#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalUnMaskTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		Q.EklundhBitTranspose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		HashValues(Q, seedbuf, vSnd, OT_ptr, min(lim - OT_ptr, OTsPerIteration), rndmat);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif

		//TODO: outsource into method
		tmpmaskbuf.otid = OT_ptr;
		tmpmaskbuf.otlen = min(lim - OT_ptr, OTsPerIteration);
		tmpmaskbuf.maskbuf = new CBitVector[numsndvals];
		for(uint32_t i = 0; i < numsndvals; i++)
			tmpmaskbuf.maskbuf[i].Copy(vSnd[i]);
		mask_queue.push(tmpmaskbuf);

		if(check_chan->data_available()) {
			assert(CheckConsistency(&check_queue, check_chan));//TODO assert
			tmpmaskbuf = mask_queue.front();
			mask_queue.pop();
			MaskAndSend(tmpmaskbuf.maskbuf, tmpmaskbuf.otid, tmpmaskbuf.otlen, ot_chan);
		}
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		OT_ptr += min(lim - OT_ptr, OTsPerIteration);
		Q.Reset();

		//free(rcvbufptr);
	}

	while(!check_queue.empty()) {
		if(check_chan->data_available()) {
			assert(CheckConsistency(&check_queue, check_chan));//TODO assert
			tmpmaskbuf = mask_queue.front();
			mask_queue.pop();
			MaskAndSend(tmpmaskbuf.maskbuf, tmpmaskbuf.otid, tmpmaskbuf.otlen, ot_chan);
		}
	}

	//vRcv.delCBitVector();
	ot_chan->synchronize_end();
	check_chan->synchronize_end();

	Q.delCBitVector();
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].delCBitVector();

	for (uint32_t i = 0; i < numsndvals; i++)
		vSnd[i].delCBitVector();
	if (numsndvals > 0)
		free(vSnd);

	if(use_mat_chan) {
		mat_chan->synchronize_end();
	}

	if(m_eSndOTFlav == Snd_GC_OT) {
		freeRndMatrix(rndmat, m_nBaseOTs);
	}
#ifdef OTTiming
	cout << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t BaseOT Unmasking:\t" << totalUnMaskTime << " ms" << endl;
	cout << "\t Check Hashing:\t" << totalHashCheckTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif


	delete ot_chan;
	delete check_chan;
	return TRUE;
}


void ALSZOTExtSnd::FillAndSendRandomMatrix(uint64_t **rndmat, channel* mat_chan) {
	if(m_eSndOTFlav == Snd_GC_OT) {
		uint8_t* rnd_seed = (uint8_t*) malloc(m_nSymSecParam);
		m_cCrypt->gen_rnd(rnd_seed, m_nSymSecParam);
		mat_chan->send(rnd_seed, m_nSymSecParam);
		fillRndMatrix(rnd_seed, rndmat, m_nBitLength, m_nBaseOTs, m_cCrypt);
		free(rnd_seed);
	}
}



snd_check_t ALSZOTExtSnd::UpdateCheckBuf(uint8_t* tocheckseed, uint8_t* tocheckrcv, uint64_t otid, uint64_t numblocks, channel* check_chan) {
	uint64_t rowbytelen = m_nBlockSizeBytes * numblocks;
	uint8_t* hash_buf = (uint8_t*) malloc(m_cCrypt->get_hash_bytes());
	uint8_t* tmpbuf = (uint8_t*) malloc(rowbytelen);
	uint8_t *idaptr, *idbptr;
	snd_check_t check_buf;
	check_buf.rcv_chk_buf = (uint8_t*) malloc(m_nChecks * OWF_BYTES);
	check_buf.seed_chk_buf = (uint8_t*) malloc(m_nChecks * OWF_BYTES);
	uint8_t *seedcheckbufptr = check_buf.seed_chk_buf, *rcvcheckbufptr = check_buf.rcv_chk_buf;

	check_buf.otid = otid;
	check_buf.numblocks = numblocks;
	check_buf.perm = (linking_t*) malloc(sizeof(linking_t*) * m_nChecks);
	genRandomPermutation(check_buf.perm, m_nBaseOTs, m_nChecks);

	//right now the rowbytelen needs to be a multiple of AES_BYTES
	assert(ceil_divide(rowbytelen, OWF_BYTES) * OWF_BYTES == rowbytelen);
#ifdef DEBUG_ALSZ_CHECKS
	cout << "rowbytelen = " << rowbytelen << endl;
	m_vU.PrintHex();
#endif

	for(uint64_t i = 0; i < m_nChecks; i++, seedcheckbufptr+=OWF_BYTES, rcvcheckbufptr+=OWF_BYTES) {
		memset(tmpbuf, 0, rowbytelen);
#ifdef DEBUG_ALSZ_CHECKS
		cout << i << "-th check between " << check_buf.perm[i].ida << " and " << check_buf.perm[i].idb << ": " << endl;
#endif
		XORandOWF(tocheckseed + check_buf.perm[i].ida * rowbytelen, tocheckseed + check_buf.perm[i].idb * rowbytelen,
				rowbytelen, tmpbuf, seedcheckbufptr, hash_buf);
		XORandOWF(tocheckrcv + check_buf.perm[i].ida * rowbytelen, tocheckrcv + check_buf.perm[i].idb * rowbytelen,
				rowbytelen, tmpbuf, rcvcheckbufptr, hash_buf);
	}

	free(tmpbuf);
	free(hash_buf);

	if(m_eSndOTFlav == Snd_GC_OT) {

	}

	//Send the permutation over to the receiver
	check_chan->send_id_len((uint8_t*) check_buf.perm, sizeof(linking_t) * m_nChecks, otid, numblocks);

	return check_buf;
}

void ALSZOTExtSnd::XORandOWF(uint8_t* idaptr, uint8_t* idbptr, uint64_t rowbytelen, uint8_t* tmpbuf,
		uint8_t* resbuf, uint8_t* hash_buf) {

	for(uint64_t j = 0; j < rowbytelen/sizeof(uint64_t); j++) {
		((uint64_t*) tmpbuf)[j] = ((uint64_t*) tmpbuf)[j] ^ ((uint64_t*) idaptr)[j] ^ ((uint64_t*) idbptr)[j];
	}

#ifdef DEBUG_ALSZ_CHECKS_INPUT
		cout << "\t" << (hex);
		for(uint32_t t = 0; t < rowbytelen; t++) {
			cout << setw(2) << setfill('0') << (uint32_t) tmpbuf[t];
		}
		cout << (dec) << endl;
#endif
#ifdef AES_OWF
		owf(&aesowfkey, rowbytelen, tmpbuf, resbuf);
#else
		m_cCrypt->hash_buf(resbuf, OWF_BYTES, tmpbuf, rowbytelen, hash_buf);//hash_buf, rowbytelen, tmpbuf, resbuf, hash_buf);
#endif
#ifdef DEBUG_ALSZ_CHECKS_OUTPUT
		cout << "\t" << (hex);
		for(uint32_t t = 0; t < OWF_BYTES; t++) {
			cout << (uint32_t) resbuf[t];
		}
		cout << (dec) << endl;
#endif
}

BOOL ALSZOTExtSnd::CheckConsistency(queue<snd_check_t>* check_buf_q, channel* check_chan) {
	uint8_t *rcvhashbufptr, *seedbufsrvptr, *rcvbufsrvptr, *rcvhashbuf;
	uint32_t ida, idb, receiver_hashes = 4;
	uint64_t checkbytelen= receiver_hashes * OWF_BYTES, tmpid, tmpnblocks, seedhashcli, rcvhashcli;

	uint8_t* rcvbuf = check_chan->blocking_receive_id_len(&rcvhashbuf, &tmpid, &tmpnblocks);
	uint8_t ca, cb;

	snd_check_t check_buf = check_buf_q->front();
	check_buf_q->pop();

	//Should be fine since the blocks are handled sequentially - but recheck anyway
	assert(check_buf.otid == tmpid);
	assert(check_buf.numblocks == tmpnblocks);

	uint32_t blockoffset = ceil_divide(check_buf.otid, NUMOTBLOCKS * m_nBlockSizeBytes);
	uint32_t offset = 0 ;//m_nBaseOTs * blockoffset;//TODO, put offset in again when 3-stop ot is implemented

	rcvhashbufptr = rcvhashbuf;

	seedbufsrvptr = check_buf.seed_chk_buf;
	rcvbufsrvptr = check_buf.rcv_chk_buf;

	for(uint32_t i = 0, j; i < m_nChecks; i++, rcvhashbufptr+=checkbytelen) {
		ida = check_buf.perm[i].ida;
		idb = check_buf.perm[i].idb;
		assert(ida < m_nBaseOTs && idb < m_nBaseOTs);

		ca = m_vU.GetBit(ida + offset);
		cb = m_vU.GetBit(idb + offset);

		//check that ida+idb == seedbufcheck and (!ida) + (!idb) == rcvbufcheck
		for(j = 0; j < ceil_divide(OWF_BYTES,sizeof(uint64_t)); j++, seedbufsrvptr+=sizeof(uint64_t), rcvbufsrvptr+=sizeof(uint64_t)) {

			seedhashcli = *(((uint64_t*) rcvhashbufptr) + (2*ca+cb)*2 + j);
			rcvhashcli = *(((uint64_t*) rcvhashbufptr) + (2*(ca^1)+(cb^1))*2 + j);


			if(seedhashcli != *((uint64_t*) seedbufsrvptr) || rcvhashcli != *((uint64_t*) rcvbufsrvptr)) {
#ifdef DEBUG_ALSZ_CHECKS
				cout << "Error in " << i <<"-th consistency check between " << ida << " and " << idb <<" : " << endl;
				cout << "Receiver seed = " << (hex) << ((uint64_t*) (rcvhashbufptr+((2*ca+cb) * OWF_BYTES)))[0] <<
						((uint64_t*) (rcvhashbufptr+((2*ca+cb) * OWF_BYTES) + j))[1] << ", my seed: " <<
						((uint64_t*) seedbufsrvptr)[0] << ((uint64_t*) seedbufsrvptr)[1] << (dec) << endl;
				cout << "Receiver sndval = " << (hex) << ((uint64_t*) (rcvhashbufptr+((2*(ca^1)+(cb^1)) * OWF_BYTES) + j))[0] <<
						((uint64_t*) (rcvhashbufptr+((2*(ca^1)+(cb^1)) * OWF_BYTES) + j))[1] << ", my snd val = " <<
						((uint64_t*) rcvbufsrvptr)[0] << ((uint64_t*) rcvbufsrvptr)[1] << (dec) << endl;
#endif
				return false;
			}
		}
	}
	//free the receive buffer
	free(rcvbuf);

	return TRUE;
}


void ALSZOTExtSnd::genRandomPermutation(linking_t* outperm, uint32_t nids, uint32_t nperms) {
	uint32_t rndbits = m_nSymSecParam * nperms;
	uint64_t bitsint = (8*sizeof(uint32_t));
	uint32_t rnditers = ceil_divide(m_cCrypt->get_seclvl().symbits, bitsint);
	CBitVector rndstring;
	rndstring.Create((uint64_t) rnditers * nperms, bitsint, m_cCrypt);

	uint64_t tmpval, tmprnd;

	for(uint32_t i = 0, rndctr=0, j; i < nperms; i++) {
		outperm[i].ida = i % nids;
		//if(outperm[i].ida == 0) outperm[i].ida++;
		for(j = 0, tmpval = 0; j < rnditers; j++, rndctr++) {
			tmprnd = rndstring.Get<uint32_t>(rndctr);
			tmpval = ((uint64_t) (tmpval << bitsint) | tmprnd);
			tmpval = tmpval % nids;
		}
		outperm[i].idb = (uint32_t) tmpval;
		//if(outperm[i].idb == 0) outperm[i].idb++;
		//cout << "Permutation " << i << ": " << outperm[i].ida << " <-> " << outperm[i].idb << endl;
	}

	rndstring.delCBitVector();
}


void ALSZOTExtSnd::ComputeBaseOTs(field_type ftype) {
	if(m_bDoBaseOTs) {
		m_cBaseOT = new SimpleOT(m_cCrypt, ftype);
		ComputePKBaseOTs();
		delete m_cBaseOT;
	} else {
		//recursive call
	}
}

/*
 * alsz-ot-ext-rec.cpp
 *
 *  Created on: Mar 23, 2015
 *      Author: mzohner
 */


#include "alsz-ot-ext-rec.h"


BOOL ALSZOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;

	uint64_t internal_numOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + internal_numOTs;

	uint64_t processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(internal_numOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t OTwindow = NUMOTBLOCKS * wd_size_bits;
	uint64_t** rndmat;
	bool use_mat_chan = (m_eSndOTFlav == Snd_GC_OT || m_bUseMinEntCorRob);
	uint32_t nchans = 2;
	if(use_mat_chan) {
		nchans = 3;
	}

	channel* ot_chan = new channel(OT_BASE_CHANNEL+nchans*id, m_cRcvThread, m_cSndThread);
	channel* check_chan = new channel(OT_BASE_CHANNEL+nchans*id+1, m_cRcvThread, m_cSndThread);
	channel* mat_chan;
	if(use_mat_chan) {
		mat_chan = new channel(nchans*id+2, m_cRcvThread, m_cSndThread);
	}

	//counter variables
	uint64_t numblocks = ceil_divide(internal_numOTs, OTsPerIteration);

	// A temporary part of the T matrix
	CBitVector T(wd_size_bits * OTsPerIteration);

	// The send buffer
	CBitVector vSnd(m_nBaseOTs * OTsPerIteration);

	// A temporary buffer that stores the resulting seeds from the hash buffer
	//TODO: Check for some maximum size
	CBitVector seedbuf(OTwindow * m_cCrypt->get_aes_key_bytes() * 8);

	uint64_t otid = myStartPos;
	queue<alsz_rcv_check_t> check_buf;

	queue<mask_block*> mask_queue;
	CBitVector maskbuf;
	maskbuf.Create(m_nBitLength * OTwindow);

	//these two values are only required for the min entropy correlation robustness assumption
	alsz_rcv_check_t check_tmp;
	CBitVector Ttmp(wd_size_bits * OTsPerIteration);

	OT_AES_KEY_CTX* tmp_base_keys;

	uint64_t base_ot_block_ctr = otid / (myNumOTs);

	//TODO only do when successfull checks
	if(m_eSndOTFlav == Snd_GC_OT) {
		initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
	}

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0,
			totalChkTime = 0, totalMaskTime = 0, totalEnqueueTime = 0, totalOutputSetTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (otid < lim) {
		processedOTBlocks = min((uint64_t) NUMOTBLOCKS, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		//nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

		tmp_base_keys = m_tBaseOTKeys[base_ot_block_ctr];
		//m_tBaseOTQ.pop();

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(&T, &vSnd, otid, processedOTBlocks, tmp_base_keys);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		check_buf.push(EnqueueSeed(T.GetArr(), vSnd.GetArr(), otid, processedOTBlocks));
#ifdef OTTiming
		totalEnqueueTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		MaskBaseOTs(&T, &vSnd, otid, processedOTBlocks);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMaskTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		SendMasks(&vSnd, ot_chan, otid, OTsPerIteration);
		//ot_chan->send_id_len(vSnd.GetArr(), nSize, otid, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif

		ReceiveAndFillMatrix(rndmat, mat_chan);
		if(!m_bUseMinEntCorRob) {
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
		}
		if(check_chan->data_available()) {
			if(m_bUseMinEntCorRob) {
				check_tmp = check_buf.front();
				Ttmp.Copy(check_tmp.T0, 0, check_tmp.numblocks * m_nBlockSizeBytes);
			}
			ComputeOWF(&check_buf, check_chan);
			if(m_bUseMinEntCorRob) {
				ReceiveAndXORCorRobVector(&Ttmp, check_tmp.numblocks * wd_size_bits, mat_chan);
				Ttmp.Transpose(wd_size_bits, OTsPerIteration);
				HashValues(&Ttmp, &seedbuf, &maskbuf, check_tmp.otid, min(lim - check_tmp.otid, check_tmp.numblocks * wd_size_bits), rndmat);
			}
#ifdef OTTiming
			gettimeofday(&tempEnd, NULL);
			totalChkTime += getMillies(tempStart, tempEnd);
			gettimeofday(&tempStart, NULL);
#endif
		}

		SetOutput(&maskbuf, otid, OTsPerIteration, &mask_queue, ot_chan);

		otid += min(lim - otid, OTsPerIteration);
		base_ot_block_ctr++;
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalOutputSetTime += getMillies(tempStart, tempEnd);
#endif

		//free(tmp_base_keys);
		//free(tmp_baseots);

		vSnd.Reset();
		T.Reset();
	}

	while(!check_buf.empty()) {
		if(check_chan->data_available()) {
			if(m_bUseMinEntCorRob) {
				check_tmp = check_buf.front();
				Ttmp.Copy(check_tmp.T0, 0, check_tmp.numblocks * m_nBlockSizeBytes);
			}
#ifdef OTTiming
			gettimeofday(&tempStart, NULL);
#endif
			ComputeOWF(&check_buf, check_chan);
#ifdef OTTiming
			gettimeofday(&tempEnd, NULL);
			totalChkTime += getMillies(tempStart, tempEnd);
#endif
			if(m_bUseMinEntCorRob) {
				ReceiveAndXORCorRobVector(&Ttmp, check_tmp.numblocks * wd_size_bits, mat_chan);
				Ttmp.Transpose(wd_size_bits, OTsPerIteration);
				HashValues(&Ttmp, &seedbuf, &maskbuf, check_tmp.otid, min(lim - check_tmp.otid, check_tmp.numblocks * wd_size_bits), rndmat);
			}
		}
	}


	if(m_eSndOTFlav != Snd_R_OT) {
		//finevent->Wait();
#ifdef ABY_OT
		while(!(mask_queue.empty())) {
#else
		while(ot_chan->is_alive() && !(mask_queue.empty())) {
#endif
#ifdef OTTiming
			gettimeofday(&tempStart, NULL);
#endif
			ReceiveAndUnMask(ot_chan, &mask_queue);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalOutputSetTime += getMillies(tempStart, tempEnd);
#endif
		}
	}

	ot_chan->synchronize_end();
	check_chan->synchronize_end();


	T.delCBitVector();
	vSnd.delCBitVector();
	seedbuf.delCBitVector();
	maskbuf.delCBitVector();
	Ttmp.delCBitVector();

	if(use_mat_chan) {
		mat_chan->synchronize_end();
	}

	if(m_eSndOTFlav==Snd_GC_OT) {
		freeRndMatrix(rndmat, m_nBaseOTs);
	}

#ifdef OTTiming
	cout << "Receiver time benchmark for performing " << internal_numOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Enqueuing Seeds:\t" << totalEnqueueTime << " ms" << endl;
	cout << "\t Base OT Masking:\t" << totalMaskTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
	cout << "\t Checking OWF:  \t" << totalChkTime << " ms" << endl;
	cout << "\t Setting Output:\t" << totalOutputSetTime << " ms" << endl;
#endif

	return TRUE;
}


void ALSZOTExtRec::ReceiveAndFillMatrix(uint64_t** rndmat, channel* mat_chan) {
	if(m_eSndOTFlav == Snd_GC_OT) {
		uint8_t* rnd_seed = mat_chan->blocking_receive();
		//initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
		fillRndMatrix(rnd_seed, rndmat, m_nBitLength, m_nBaseOTs, m_cCrypt);
		free(rnd_seed);
	}
}

alsz_rcv_check_t ALSZOTExtRec::EnqueueSeed(uint8_t* T0, uint8_t* T1, uint64_t otid, uint64_t numblocks) {
	uint64_t expseedbytelen = m_nBaseOTs * numblocks * m_nBlockSizeBytes;
	alsz_rcv_check_t seedstr;

	seedstr.otid = otid;
	seedstr.numblocks = numblocks;
	seedstr.T0 = (uint8_t*) malloc(expseedbytelen);
	seedstr.T1 = (uint8_t*) malloc(expseedbytelen);

	memcpy(seedstr.T0, T0, expseedbytelen);
	memcpy(seedstr.T1, T1, expseedbytelen);

	return seedstr;
}



void ALSZOTExtRec::ComputeOWF(queue<alsz_rcv_check_t>* check_buf_q, channel* check_chan) {//linking_t* permbits, int nchecks, int otid, int processedOTs, BYTE* outhashes) {

	//Obtain T0 and T1 from the SeedPointers
	BOOL found = false;
	uint32_t receiver_hashes = 4;

	uint64_t tmpid, tmpnblocks;
	linking_t* perm;
	uint8_t* rcv_buf = check_chan->blocking_receive_id_len((uint8_t**) &perm, &tmpid, &tmpnblocks);

	alsz_rcv_check_t check_buf = check_buf_q->front();
	check_buf_q->pop();

	assert(tmpid == check_buf.otid);
	assert(tmpnblocks == check_buf.numblocks);

	//the bufsize has to be padded to a multiple of the PRF-size since we will omit boundary checks there
	uint32_t i, k, j;
	uint64_t bufrowbytelen = m_nBlockSizeBytes * check_buf.numblocks;//seedptr->expstrbitlen>>3;//(CEIL_DIVIDE(processedOTs, wd_size_bits) * wd_size_bits) >>3;
	//contains the T-matrix
	uint8_t* T0 = check_buf.T0;
	//contains the T-matrix XOR the receive bits
	uint8_t* T1 = check_buf.T1;

	uint8_t* T0ptr = T0;
	uint8_t* T1ptr = T1;

	uint32_t outhashbytelen = m_nChecks * OWF_BYTES * receiver_hashes;
	uint8_t* outhashes = (uint8_t*) malloc(outhashbytelen);

#ifdef OTTiming_PRECISE
	timeval tstart, tend;
	double total_xortime = 0, total_hashtime = 0;
#endif

#ifdef AES_OWF
	AES_KEY_CTX aesowfkey;
	MPC_AES_KEY_INIT(&aesowfkey);
#else
	uint8_t* hash_buf = (uint8_t*) malloc(SHA512_DIGEST_LENGTH);
#endif
	//uint8_t* tmpbuf = (uint8_t**) malloc(bufrowbytelen);
	uint8_t** tmpbuf = (uint8_t**) malloc(receiver_hashes * sizeof(uint8_t*));
	for(i = 0; i < receiver_hashes; i++) {
		tmpbuf[i] = (uint8_t*) malloc(bufrowbytelen);
	}

	uint8_t **ka = (uint8_t**) malloc(2);
	uint8_t **kb = (uint8_t**) malloc(2);
	uint8_t  *kaptr, *kbptr;
	uint8_t* outptr = outhashes;
	uint32_t ida, idb;
	uint32_t iters = bufrowbytelen / sizeof(uint64_t);

	SHA512_CTX sha, shatmp;
	SHA512_Init(&sha);
	SHA512_Init(&shatmp);
	//Compute all hashes for the permutations given Ta and Tb
	for(i = 0; i < m_nChecks; i++) {
		ka[0] = T0 + perm[i].ida * bufrowbytelen;
		ka[1] = T1 + perm[i].ida * bufrowbytelen;

		kb[0] = T0 + perm[i].idb * bufrowbytelen;
		kb[1] = T1 + perm[i].idb * bufrowbytelen;
		//cout << "ida = " << perm[i].ida <<", idb= " <<  perm[i].idb << endl;

		//XOR all four possibilities
#ifdef DEBUG_ALSZ_CHECKS
		cout << i << "-th check: between " << perm[i].ida << ", and " << perm[i].idb << ": " << endl;
#endif

		for(k = 0; k < iters; k++) {
			((uint64_t*) tmpbuf[0])[k] = ((uint64_t*) ka[0])[k] ^ ((uint64_t*) kb[0])[k];
			((uint64_t*) tmpbuf[1])[k] = ((uint64_t*) ka[0])[k] ^ ((uint64_t*) kb[1])[k];
			((uint64_t*) tmpbuf[2])[k] = ((uint64_t*) ka[1])[k] ^ ((uint64_t*) kb[0])[k];
			((uint64_t*) tmpbuf[3])[k] = ((uint64_t*) ka[1])[k] ^ ((uint64_t*) kb[1])[k];
		}
		sha = shatmp;
		//sha512_hash(outptr, OWF_BYTES, tmpbuf[0], bufrowbytelen, hash_buf);
		SHA512_Update(&sha, tmpbuf[0], bufrowbytelen);
		SHA512_Final(hash_buf, &sha);
		memcpy(outptr, hash_buf, OWF_BYTES);
		outptr+=OWF_BYTES;
		//sha512_hash(outptr, OWF_BYTES, tmpbuf[1], bufrowbytelen, hash_buf);
		sha = shatmp;
		SHA512_Update(&sha, tmpbuf[1], bufrowbytelen);
		SHA512_Final(hash_buf, &sha);
		memcpy(outptr, hash_buf, OWF_BYTES);
		outptr+=OWF_BYTES;
		//sha512_hash(outptr, OWF_BYTES, tmpbuf[2], bufrowbytelen, hash_buf);
		sha = shatmp;
		SHA512_Update(&sha, tmpbuf[2], bufrowbytelen);
		SHA512_Final(hash_buf, &sha);
		memcpy(outptr, hash_buf, OWF_BYTES);
		outptr+=OWF_BYTES;
		//sha512_hash(outptr, OWF_BYTES, tmpbuf[3], bufrowbytelen, hash_buf);
		sha = shatmp;
		SHA512_Update(&sha, tmpbuf[3], bufrowbytelen);
		SHA512_Final(hash_buf, &sha);
		memcpy(outptr, hash_buf, OWF_BYTES);
		outptr+=OWF_BYTES;

/*		for(j = 0; j < receiver_hashes; j++, outptr+=OWF_BYTES) {
#ifdef OTTiming_PRECISE
			gettimeofday(&tstart, NULL);
#endif
			kaptr = ka[j>>1];
			kbptr = kb[j&0x01];

			for(k = 0; k < iters; k++) {
				((uint64_t*) tmpbuf)[k] = ((uint64_t*) kaptr)[k] ^ ((uint64_t*) kbptr)[k];
			}
#ifdef DEBUG_ALSZ_CHECKS_INPUT
			cout << (hex)  <<  "\t";
			for(uint32_t t = 0; t < bufrowbytelen; t++) {
				cout << setw(2) << setfill('0') << (uint32_t) tmpbuf[t];
			}
			cout << (dec) << endl;
#endif

#ifdef AES_OWF
			owf(&aesowfkey, rowbytelen, tmpbuf, outptr);
#else
	#ifdef OTTiming_PRECISE
			gettimeofday(&tend, NULL);
			total_xortime += getMillies(tstart, tend);
			gettimeofday(&tstart, NULL);
	#endif
			sha512_hash(outptr, OWF_BYTES, tmpbuf, bufrowbytelen, hash_buf);

			//m_cCrypt->hash_buf(outptr, OWF_BYTES, tmpbuf, bufrowbytelen, hash_buf);
	#ifdef OTTiming_PRECISE
			gettimeofday(&tend, NULL);
			total_hashtime += getMillies(tstart, tend);
	#endif
#endif
#ifdef DEBUG_ALSZ_CHECKS_OUTPUT
			cout << (hex) << "\t";
			for(uint32_t t = 0; t < OWF_BYTES; t++) {
				cout << (uint32_t) outptr[t];
			}
			cout << (dec) << endl;
#endif
		}*/
	}

	check_chan->send_id_len(outhashes, outhashbytelen, check_buf.otid, check_buf.numblocks);
#ifdef OTTiming_PRECISE
	cout << "Total XOR Time:\t" << total_xortime << " ms"<< endl;
	cout << "Total Hash Time:\t" << total_hashtime << " ms"<< endl;
#endif

	free(rcv_buf);
	for(uint32_t i = 0; i < receiver_hashes; i++)
		free(tmpbuf[i]);
	free(tmpbuf);
	free(ka);
	free(kb);
	free(check_buf.T0);
	free(check_buf.T1);
#ifndef AES_OWF
	free(hash_buf);
#endif
}

void ALSZOTExtRec::ComputeBaseOTs(field_type ftype) {
	/*m_cBaseOT = new SimpleOT(m_cCrypt, ftype);
	ComputePKBaseOTs();
	delete m_cBaseOT;*/
	uint32_t nsndvals = 2;

	if(m_bDoBaseOTs) { //use public-key crypto routines (simple OT)
		m_cBaseOT = new SimpleOT(m_cCrypt, ftype);
		ComputePKBaseOTs();
		delete m_cBaseOT;

		/*base_ots_snd_t* tmp = (base_ots_snd_t*) malloc(sizeof(base_ots_snd_t));
		tmp->base_ot_key_ptr = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nBaseOTs * nsndvals);
		memcpy(tmp->base_ot_key_ptr, m_vBaseOTKeys, sizeof(AES_KEY_CTX) * m_nBaseOTs * nsndvals);
		m_tBaseOTQ.push_back(tmp);*/
	} else {
		ALSZOTExtSnd* snd = new ALSZOTExtSnd(m_cCrypt, m_cRcvThread, m_cSndThread, m_nBaseOTs, m_nChecks);
		uint32_t numots = BUFFER_OT_KEYS * m_nBaseOTs;
		XORMasking* m_fMaskFct = new XORMasking(m_cCrypt->get_seclvl().symbits);
		CBitVector** X = (CBitVector**) malloc(sizeof(CBitVector*) * nsndvals);//new CBitVector[nsndvals];
		uint32_t secparambytes = bits_in_bytes(m_cCrypt->get_seclvl().symbits);
		uint8_t* buf;

		for(uint32_t i = 0; i < nsndvals; i++) {
			X[i] = new CBitVector();
			X[i]->Create(numots * m_cCrypt->get_seclvl().symbits);
		}
		//X1.Create(numots * m_cCrypt->get_seclvl().symbits);

		snd->computePKBaseOTs();
		snd->ComputeBaseOTs(ftype);

		snd->send(numots, m_cCrypt->get_seclvl().symbits, nsndvals, X, Snd_R_OT, Rec_R_OT, 1, m_fMaskFct);

		//assign keys to base OT queue
		buf = (uint8_t*) malloc(secparambytes * nsndvals * m_nBaseOTs);

		OT_AES_KEY_CTX* tmp_keys;
		for(uint32_t i = 0; i < BUFFER_OT_KEYS; i++) {
			//base_ots_snd_t* tmp = (base_ots_snd_t*) malloc(sizeof(base_ots_snd_t));
			tmp_keys = (OT_AES_KEY_CTX*) malloc(sizeof(OT_AES_KEY_CTX) * m_nBaseOTs * nsndvals);
			/*for(uint32_t j = 0; j < m_nBaseOTs; j++) {
				memcpy(buf + j * nsndvals * secparambytes, X0.GetArr() + (i * m_nBaseOTs + j) * secparambytes, secparambytes);
				memcpy(buf + (j * nsndvals + 1) * secparambytes, X1.GetArr() + (i * m_nBaseOTs + j) * secparambytes, secparambytes);
			}*/
			memcpy(buf, X[0]->GetArr() + secparambytes * m_nBaseOTs * i, secparambytes * m_nBaseOTs);
			memcpy(buf + secparambytes * m_nBaseOTs, X[1]->GetArr() + secparambytes * m_nBaseOTs * i, secparambytes * m_nBaseOTs);
			InitAESKey(tmp_keys, buf, nsndvals * m_nBaseOTs, m_cCrypt);
			m_tBaseOTKeys.push_back(tmp_keys);
		}

		free(buf);
		for(uint32_t i = 0; i < nsndvals; i++) {
			X[i]->delCBitVector();
		}
		//free(X);
	//	X0.delCBitVector();
	//	X1.delCBitVector();
		delete m_fMaskFct;
		delete snd;
	}

}

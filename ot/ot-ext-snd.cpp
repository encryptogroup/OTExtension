/**
 \file 		ot-ex-snd.cpp
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 ENCRYPTO Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief
 */

#include <algorithm>
#include <memory>
#include <iostream>
#include <sys/time.h>
#include <vector>
#include "ot-ext-snd.h"
#include "baseOT.h"
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/cbitvector.h>
#ifdef OTTiming
#include <ENCRYPTO_utils/timer.h>
#endif

BOOL OTExtSnd::send(uint64_t numOTs, uint64_t bitlength, uint64_t nsndvals, CBitVector** X, snd_ot_flavor stype,
		rec_ot_flavor rtype, uint32_t numThreads, MaskingFunction* maskfct) {
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_nSndVals = nsndvals;
	m_vValues = X;
	//m_vValues[0] = x0;
	//m_vValues[1] = x1;
	m_eSndOTFlav = stype;
	m_eRecOTFlav = rtype;
	m_fMaskFct = maskfct;

	assert(pad_to_power_of_two(m_nSndVals) == m_nSndVals);

	return start_send(numThreads);
}

//Initialize and start numThreads OTSenderThread
BOOL OTExtSnd::start_send(uint32_t numThreads) {
	if (m_nOTs == 0)
		return true;

	if(numThreads * m_nBlockSizeBits > m_nOTs && numThreads > 1) {
		std::cerr << "Decreasing nthreads from " << numThreads << " to " << std::max(m_nOTs / m_nBlockSizeBits, (uint64_t) 1) << " to fit window size\n";
		numThreads = std::max(m_nOTs / m_nBlockSizeBits, (uint64_t) 1);
	}

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint32_t wd_size_bits = m_nBlockSizeBits;//pad_to_power_of_two(m_nBaseOTs);//1 << (ceil_log2(m_nBaseOTs));
	//uint64_t numOTs = ceil_divide(PadToMultiple(m_nOTs, wd_size_bits), numThreads);
	uint64_t internal_numOTs = PadToMultiple(ceil_divide(m_nOTs, numThreads), wd_size_bits);
	std::vector<OTSenderThread*> sThreads(numThreads);

	for (uint32_t i = 0; i < numThreads; i++) {
		sThreads[i] = new OTSenderThread(i, internal_numOTs, this);
		sThreads[i]->Start();
	}

	for (uint32_t i = 0; i < numThreads; i++) {
		sThreads[i]->Wait();
	}

	m_nCounter += m_nOTs;

	for (uint32_t i = 0; i < numThreads; i++) {
		delete sThreads[i];
	}

	if (verify_ot) {
		verifyOT(m_nOTs);
	}

	return true;
}


void OTExtSnd::BuildQMatrix(CBitVector* T, uint64_t OT_ptr, uint64_t numblocks, OT_AES_KEY_CTX* seedkeyptr) {
	BYTE* Tptr = T->GetArr();
	uint8_t* ctr_buf = (uint8_t*) calloc (AES_BYTES, sizeof(uint8_t));
	uint64_t* counter = (uint64_t*) ctr_buf;
	uint64_t wd_size_bytes = m_nBlockSizeBytes;//pad_to_power_of_two(m_nBaseOTs/8);//1 << (ceil_log2(m_nBaseOTs) - 3);
	uint64_t rowbytelen = wd_size_bytes * numblocks;

	//AES_KEY_CTX* seedptr = m_vBaseOTKeys;
	uint64_t global_OT_ptr = OT_ptr + m_nCounter;

	uint64_t iters = rowbytelen / AES_BYTES;


#ifdef USE_PIPELINED_AES_NI
	intrin_sequential_gen_rnd8(ctr_buf, global_OT_ptr, Tptr, iters, m_nBaseOTs, seedkeyptr);
#else
	for (uint64_t k = 0, b; k < m_nBaseOTs; k++) {
		*counter = global_OT_ptr;
		for (b = 0; b < iters; b++, (*counter)++, Tptr += AES_BYTES) {
			m_cCrypt->encrypt(seedkeyptr + k, Tptr, ctr_buf, AES_BYTES);
#ifdef DEBUG_MALICIOUS
			std::cout << "k = " << k << ": "<< (std::hex) << ((uint64_t*) Tptr)[0] << ((uint64_t*) Tptr)[1] << (std::hex) << std::endl;
#endif
		}
#ifdef DEBUG_OT_SEED_EXPANSION
		std::cout << "Xs[" << k << "]: " << (std::hex);
		for(uint64_t i = 0; i < AES_BYTES * iters; i++) {
			std::cout  << std::setw(2) << std::setfill('0') << (uint32_t) (Tptr-AES_BYTES*iters)[i];
		}
		std::cout << (std::dec) << " (" << (*counter)-iters << ")" <<std::endl;
#endif
	}
#endif
	free(ctr_buf);
}

//XOR m_nU on top
void OTExtSnd::UnMaskBaseOTs(CBitVector* T, CBitVector* RcvBuf, CBitVector* U, uint64_t numblocks) {
	uint64_t rowbytelen = m_nBlockSizeBytes * numblocks;
	uint8_t* rcvbufptr = RcvBuf->GetArr();
#ifdef GENERATE_T_EXPLICITELY
	uint64_t blocksizebytes = m_nBaseOTs * rowbytelen;
#endif

	for (uint64_t k = 0; k < m_nBaseOTs; k++, rcvbufptr += rowbytelen) {
#ifdef GENERATE_T_EXPLICITELY
		if (U->GetBit(k) == 0) {
			T->XORBytes(rcvbufptr, k * rowbytelen, rowbytelen);
		} else {
			T->XORBytes(rcvbufptr + blocksizebytes, k * rowbytelen, rowbytelen);
		}
#else
		if (U->GetBit(k)) {
			T->XORBytes(rcvbufptr, k * rowbytelen, rowbytelen);
		}
#endif

	}
}

void OTExtSnd::ReceiveMasks(CBitVector* vRcv, channel* chan, uint64_t processedOTs, uint64_t rec_r_ot_startpos) {
	//uint64_t nSize = bits_in_bytes(m_nBaseOTs * processedOTs);
	uint64_t tmpctr, tmpotlen;
	uint32_t startpos = 0;
	uint8_t *rcvbuftmpptr, *rcvbufptr;

	rcvbufptr = chan->blocking_receive_id_len(&rcvbuftmpptr, &tmpctr, &tmpotlen);

	if(m_eRecOTFlav == Rec_R_OT) {
		startpos = rec_r_ot_startpos;
#ifdef GENERATE_T_EXPLICITELY
		vRcv->SetBytesToZero(0, 2* bits_in_bytes(processedOTs));
#else
		vRcv->SetBytesToZero(0, bits_in_bytes(processedOTs));
#endif
	}
#ifdef GENERATE_T_EXPLICITELY
	if(m_eRecOTFlav == Rec_R_OT) {
		vRcv->SetBytes(rcvbuftmpptr, bits_in_bytes(processedOTs), bits_in_bytes((m_nBaseOTs -startpos) * processedOTs));//AttachBuf(rcvbuftmpptr, bits_in_bytes(m_nBaseOTs * OTsPerIteration));
		vRcv->SetBytes(rcvbuftmpptr + bits_in_bytes((m_nBaseOTs -startpos) * processedOTs), bits_in_bytes(m_nBaseOTs * processedOTs), bits_in_bytes((m_nBaseOTs -startpos) * processedOTs));
	} else {
		vRcv->SetBytes(rcvbuftmpptr, 0, 2 * bits_in_bytes(m_nBaseOTs* processedOTs));//AttachBuf(rcvbuftmpptr, bits_in_bytes(m_nBaseOTs * OTsPerIteration));
	}
#else
	vRcv->SetBytes(rcvbuftmpptr, bits_in_bytes(startpos * processedOTs), bits_in_bytes((m_nBaseOTs - startpos) * processedOTs));//AttachBuf(rcvbuftmpptr, bits_in_bytes(m_nBaseOTs * OTsPerIteration));
#endif
	free(rcvbufptr);
}

void OTExtSnd::GenerateSendAndXORCorRobVector(CBitVector* Q, uint64_t OT_len, channel* chan) {
	if(m_bUseMinEntCorRob) {
		uint64_t len = bits_in_bytes(m_nBaseOTs * OT_len);
		uint8_t* rndvec = (uint8_t*) malloc(len);
		m_cCrypt->gen_rnd(rndvec, len);
		Q->XORBytes(rndvec, len);
		chan->send(rndvec, len);
		free(rndvec);
	}
}


void OTExtSnd::HashValues(CBitVector* Q, CBitVector* seedbuf, CBitVector* snd_buf, CBitVector* U,
		uint64_t OT_ptr, uint64_t OT_len, uint64_t** mat_mul) {
	// uint64_t numhashiters = ceil_divide(m_nBitLength, m_cCrypt->get_hash_bytes());
	uint32_t rowbytelen = bits_in_bytes(m_nBaseOTs);
	uint32_t hashinbytelen = rowbytelen + sizeof(uint64_t);
	uint64_t wd_size_bytes = m_nBlockSizeBytes;//1 << (ceil_log2(m_nBaseOTs) - 3);
	uint32_t u;
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();


	uint64_t* Qptr = (uint64_t*) Q->GetArr();
	uint64_t* Uptr = (uint64_t*) U->GetArr();

	uint8_t** sbp = (uint8_t**) malloc(sizeof(uint8_t*) * m_nSndVals);
	uint8_t* inbuf = (uint8_t*) calloc(hashinbytelen, 1);
	uint8_t* resbuf = (uint8_t*) calloc(m_cCrypt->get_hash_bytes(), 1);
	uint8_t* hash_buf = (uint8_t*) calloc(m_cCrypt->get_hash_bytes(), 1);

	uint64_t* tmpbuf = (uint64_t*) calloc(PadToMultiple(bits_in_bytes(m_nBitLength), sizeof(uint64_t)), 1);
	uint8_t* tmpbufb = (uint8_t*) calloc(bits_in_bytes(m_nBitLength), 1);

	uint64_t global_OT_ptr = OT_ptr + m_nCounter;

	for (u = 0; u < m_nSndVals; u++)
		sbp[u] = seedbuf[u].GetArr();

	for (uint64_t i = 0; i < OT_len; global_OT_ptr++, i++, Qptr += 2) {
		for (u = 0; u < m_nSndVals; u++) {

#ifdef HIGH_SPEED_ROT_LT
			if(u == 1) {
				Qptr[0]^=Uptr[0];
				Qptr[1]^=Uptr[1];
			}
#else
			if (u == 1)
				Q->XORBytes((uint8_t*) Uptr, i * wd_size_bytes, rowbytelen);
#endif

#ifdef DEBUG_OT_HASH_IN
			std::cout << "Hash-In for i = " << global_OT_ptr << ", u = " << u << ": " << (std::hex);
			for(uint32_t p = 0; p < rowbytelen; p++)
				std::cout << std::setw(2) << std::setfill('0') << (uint32_t) (Q.GetArr() + i * wd_size_bytes)[p];
			std::cout << (std::dec) << std::endl;
#endif

			if(m_eSndOTFlav != Snd_GC_OT) {
				if (use_fixed_key_aes_hashing) {
					FixedKeyHashing(m_kCRFKey, sbp[u], (BYTE*) Qptr, hash_buf, i, ceil_divide(m_nSymSecParam, 8), m_cCrypt);
				} else {
					memcpy(inbuf, &global_OT_ptr, sizeof(uint64_t));
					memcpy(inbuf+sizeof(uint64_t), Q->GetArr() + i * wd_size_bytes, rowbytelen);
					m_cCrypt->hash_buf(resbuf, aes_key_bytes, inbuf, hashinbytelen, hash_buf);
					memcpy(sbp[u], resbuf, aes_key_bytes);
				}
			} else {

				BitMatrixMultiplication(tmpbufb, bits_in_bytes(m_nBitLength), Q->GetArr() + i * wd_size_bytes, m_nBaseOTs, mat_mul, tmpbuf);
				//m_vValues[u].SetBits(tmpbufb, (OT_ptr + i)* m_nBitLength, m_nBitLength);
				snd_buf[u].SetBits(tmpbufb, i * m_nBitLength, m_nBitLength);
					//m_vTempOTMasks.SetBytes(tmpbufb, (uint64_t) (OT_ptr + i) * aes_key_bytes, (uint64_t) aes_key_bytes);
				//m_vValues[u].SetBytes(Q.GetArr() + i * wd_size_bytes, (OT_ptr + i)* wd_size_bytes, rowbytelen);

			}

#ifdef DEBUG_OT_HASH_OUT
			std::cout << "Hash-Out for i = " << global_OT_ptr << ", u = " << u << ": " << (std::hex);
			for(uint32_t p = 0; p < aes_key_bytes; p++)
				std::cout << std::setw(2) << std::setfill('0') << (uint32_t) sbp[u][p];
			std::cout << (std::dec) << std::endl;
#endif
			sbp[u] += aes_key_bytes;

		}
	}
	//m_vValues[0].PrintHex();
	//m_vValues[1].PrintHex();

#ifndef HIGH_SPEED_ROT_LT
	if(m_eSndOTFlav != Snd_GC_OT) {
	//Two calls to expandMask, both writing into snd_buf
		for (uint32_t u = 0; u < m_nSndVals; u++)
			m_fMaskFct->expandMask(&(snd_buf[u]), seedbuf[u].GetArr(), 0, OT_len, m_nBitLength, m_cCrypt);
	}
#endif

	free(resbuf);
	free(inbuf);
	free(sbp);
	free(hash_buf);
	free(tmpbuf);
	free(tmpbufb);
}

void OTExtSnd::MaskAndSend(CBitVector* snd_buf, uint64_t OT_ptr, uint64_t OT_len, channel* chan) {
	m_fMaskFct->Mask(OT_ptr, OT_len, m_vValues, snd_buf, m_eSndOTFlav);

	if (m_eSndOTFlav == Snd_R_OT || m_eSndOTFlav == Snd_GC_OT)
		return;

	uint64_t bufsize = bits_in_bytes(OT_len * m_nBitLength);
	uint8_t* buf = nullptr;
	if (m_eSndOTFlav == Snd_OT) {
		buf = (uint8_t*) malloc(2*bufsize);
		memcpy(buf, snd_buf[0].GetArr(), bufsize);
		memcpy(buf+ bufsize, snd_buf[1].GetArr(), bufsize);
		bufsize *= 2;
	} else if (m_eSndOTFlav == Snd_C_OT) {
		buf = (uint8_t*) malloc(bufsize);
		memcpy(buf, snd_buf[1].GetArr(), bufsize);
	}

	chan->send_id_len(buf, bufsize, OT_ptr, OT_len);
	free(buf);
}


BOOL OTExtSnd::verifyOT(uint64_t NumOTs) {
	std::cout << "Verifying 1oo"<< m_nSndVals << " OT" << std::endl;
	uint64_t processedOTBlocks, OTsPerIteration;
	uint64_t nSnd;
	uint8_t* resp;

	std::unique_ptr<channel> chan = std::make_unique<channel>(OT_ADMIN_CHANNEL, m_cRcvThread, m_cSndThread);

	for (uint64_t i = 0; i < NumOTs; i += OTsPerIteration) {
		processedOTBlocks = std::min(num_ot_blocks, ceil_divide(NumOTs - i, AES_BITS));
		OTsPerIteration = std::min(processedOTBlocks * AES_BITS, NumOTs - i);
		nSnd = ceil_divide(OTsPerIteration * m_nBitLength, 8);

		for(uint64_t j = 0; j < m_nSndVals; j++) {
			chan->send_id_len(m_vValues[j]->GetArr() + bits_in_bytes(i * m_nBitLength), nSnd, i, OTsPerIteration);
		}

		resp = chan->blocking_receive();

		if (*resp == 0x00) {
			std::cerr << "\033[1;31mError: Receiver notified us of failed OT verification.\033[0m" << std::endl;
			free(resp);
			chan->synchronize_end();
			return false;
		}
		free(resp);
	}

	std::cout << "OT Verification successful" << std::flush << std::endl;
	chan->synchronize_end();

	return true;
}


void OTExtSnd::ComputePKBaseOTs() {
	channel* chan = new channel(OT_ADMIN_CHANNEL, m_cRcvThread, m_cSndThread);
	uint8_t* pBuf = (uint8_t*) malloc(m_cCrypt->get_hash_bytes() * m_nBaseOTs);
	uint8_t* keyBuf = (uint8_t*) malloc(m_cCrypt->get_aes_key_bytes() * m_nBaseOTs);

	uint32_t nsndvals = 2;

	CBitVector* U = new CBitVector();
	U->Create(m_nBaseOTs, m_cCrypt);
	//m_vU.Copy(U.GetArr(), 0, bits_in_bytes(nbaseOTs));
	//fill zero into the remaining positions - is needed if nbaseots is not a multiple of 8
	for (uint32_t i = m_nBaseOTs; i < PadToMultiple(m_nBaseOTs, 8); i++)
		U->SetBit(i, 0);
	OT_AES_KEY_CTX* tmpkeybuf = (OT_AES_KEY_CTX*) malloc(sizeof(OT_AES_KEY_CTX) * m_nBaseOTs);

#ifdef OTTiming
	timespec np_begin, np_end;
	clock_gettime(CLOCK_MONOTONIC, &np_begin);
#endif	

	m_cBaseOT->Receiver(nsndvals, m_nBaseOTs, U, chan, pBuf);
	

#ifdef OTTiming
	clock_gettime(CLOCK_MONOTONIC, &np_end);
	printf("Time for performing the base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif

	//Key expansion
	uint8_t* pBufIdx = pBuf;
	for(uint32_t i=0; i<m_nBaseOTs; i++ )
	{
		memcpy(keyBuf + i * m_cCrypt->get_aes_key_bytes(), pBufIdx, m_cCrypt->get_aes_key_bytes());
		pBufIdx+=m_cCrypt->get_hash_bytes();
	}

 	free(pBuf);

 	InitPRFKeys(tmpkeybuf, keyBuf, m_nBaseOTs);


 	m_tBaseOTKeys.push_back(tmpkeybuf);
	m_tBaseOTChoices.push_back(U);


 	free(keyBuf);
	chan->synchronize_end();

 	delete chan;
}

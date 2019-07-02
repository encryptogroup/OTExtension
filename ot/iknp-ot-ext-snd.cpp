/**
 \file 		iknp-ot-ext-snd.cpp
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

#include "iknp-ot-ext-snd.h"
#include "naor-pinkas.h"
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/cbitvector.h>

//BOOL OTsender(int nSndVals, int nOTs, int startpos, CSocket& sock, CBitVector& U, AES_KEY* vKeySeeds, CBitVector* values, BYTE* seed)
BOOL IKNPOTExtSnd::sender_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;
	uint64_t processedOTBlocks = std::min(num_ot_blocks, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	channel* chan = new channel(OT_BASE_CHANNEL+id, m_cRcvThread, m_cSndThread);
	uint64_t** rndmat;

	myNumOTs = std::min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
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
	std::cout << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << std::endl;
#endif
	vSnd = new CBitVector[numsndvals];
	for (uint32_t i = 0; i < numsndvals; i++) {
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Contains the parts of the V matrix
	CBitVector Q(wd_size_bits * OTsPerIteration);

	uint64_t otid = myStartPos;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalUnMaskTime=0;
	timespec tempStart, tempEnd;
#endif

	if(m_eSndOTFlav == Snd_GC_OT) {
		uint8_t* rnd_seed = (uint8_t*) malloc(m_nSymSecParam);
		m_cCrypt->gen_rnd(rnd_seed, m_nSymSecParam);
		chan->send(rnd_seed, m_nSymSecParam);
		initRndMatrix(&rndmat, m_nBitLength, m_nBaseOTs);
		fillRndMatrix(rnd_seed, rndmat, m_nBitLength, m_nBaseOTs, m_cCrypt);
		free(rnd_seed);
	}

	while (otid < lim) //do while there are still transfers missing
	{
		processedOTBlocks = std::min(num_ot_blocks, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;

#ifdef ZDEBUG
		std::cout << "Sender thread " << id << " processing block " << otid <<
				" with length: " << OTsPerIteration << ", and limit: " << lim << std::endl;
#endif

#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		ReceiveMasks(&vRcv, chan, OTsPerIteration);

#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalRcvTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		BuildQMatrix(&Q, otid, processedOTBlocks, m_tBaseOTKeys.front());
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalMtxTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		UnMaskBaseOTs(&Q, &vRcv, m_tBaseOTChoices.front(), processedOTBlocks);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalUnMaskTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		Q.Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalTnsTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		HashValues(&Q, seedbuf, vSnd, m_tBaseOTChoices.front(), otid, std::min(lim - otid, OTsPerIteration), rndmat);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalHshTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		MaskAndSend(vSnd, otid, std::min(lim - otid, OTsPerIteration), chan);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		otid += std::min(lim - otid, OTsPerIteration);
		Q.Reset();
	}

#ifdef ZDEBUG
	std::cout << "Sender thread " << id << " finished " << std::endl;
#endif

	vRcv.delCBitVector();
	chan->synchronize_end();

	Q.delCBitVector();
	delete[] seedbuf;
	delete[] vSnd;

	if(m_eSndOTFlav==Snd_GC_OT)
		freeRndMatrix(rndmat, m_nBaseOTs);

#ifdef OTTiming
	std::cout << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << std::endl;
	std::cout << "Time needed for: " << std::endl;
	std::cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << std::endl;
	std::cout << "\t Unmasking values:\t" << totalUnMaskTime << " ms" << std::endl;
	std::cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << std::endl;
	std::cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << std::endl;
	std::cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << std::endl;
	std::cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << std::endl;
#endif

	delete chan;

	return TRUE;
}


void IKNPOTExtSnd::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	delete m_cBaseOT;
}

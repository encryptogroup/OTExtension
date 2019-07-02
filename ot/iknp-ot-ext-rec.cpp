/**
 \file 		iknp-ot-ext-rec.cpp
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


#include "iknp-ot-ext-rec.h"
#include "naor-pinkas.h"
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/cbitvector.h>


BOOL IKNPOTExtRec::receiver_routine(uint32_t id, uint64_t myNumOTs) {
	uint64_t myStartPos = id * myNumOTs;
	uint64_t wd_size_bits = m_nBlockSizeBits;

	myNumOTs = std::min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint64_t lim = myStartPos + myNumOTs;

	uint64_t processedOTBlocks = std::min(num_ot_blocks, ceil_divide(myNumOTs, wd_size_bits));
	uint64_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint64_t OTwindow = num_ot_blocks * wd_size_bits;
	uint64_t** rndmat;
	channel* chan = new channel(OT_BASE_CHANNEL+id, m_cRcvThread, m_cSndThread);

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

	std::queue<mask_block*> mask_queue;

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
	timespec tempStart, tempEnd;
#endif

	while (otid < lim) {
		processedOTBlocks = std::min(num_ot_blocks, ceil_divide(lim - otid, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		//nSize = bits_in_bytes(m_nBaseOTs * OTsPerIteration);

#ifdef ZDEBUG
		std::cout << "Receiver thread " << id << " processing block " << otid <<
				" with length: " << OTsPerIteration << ", and limit: " << lim << std::endl;
#endif


#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		BuildMatrices(&T, &vSnd, otid, processedOTBlocks, m_tBaseOTKeys.front());
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalMtxTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		MaskBaseOTs(&T, &vSnd, otid, processedOTBlocks);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalMaskTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		T.Transpose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalTnsTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		HashValues(&T, &seedbuf, &maskbuf, otid, std::min(lim - otid, OTsPerIteration), rndmat);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalHshTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		SendMasks(&vSnd, chan, otid, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
		totalSndTime += getMillies(tempStart, tempEnd);
		clock_gettime(CLOCK_MONOTONIC, &tempStart);
#endif
		SetOutput(&maskbuf, otid, OTsPerIteration, &mask_queue, chan);//ReceiveAndUnMask(chan);

		//counter += std::min(lim - OT_ptr, OTsPerIteration);
		otid += std::min(lim - otid, OTsPerIteration);
#ifdef OTTiming
		clock_gettime(CLOCK_MONOTONIC, &tempEnd);
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
	std::cout << "Receiver thread " << id << " finished " << std::endl;
#endif


	chan->synchronize_end();

	if(m_eSndOTFlav==Snd_GC_OT)
		freeRndMatrix(rndmat, m_nBaseOTs);
#ifdef OTTiming
	std::cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << std::endl;
	std::cout << "Time needed for: " << std::endl;
	std::cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << std::endl;
	std::cout << "\t Base OT Masking:\t" << totalMaskTime << " ms" << std::endl;
	std::cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << std::endl;
	std::cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << std::endl;
	std::cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << std::endl;
	std::cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << std::endl;
#endif

	T.delCBitVector();
	vSnd.delCBitVector();
	seedbuf.delCBitVector();
	maskbuf.delCBitVector();
	delete chan;

	return TRUE;
}


void IKNPOTExtRec::ComputeBaseOTs(field_type ftype) {
	m_cBaseOT = new NaorPinkas(m_cCrypt, ftype);
	ComputePKBaseOTs();
	delete m_cBaseOT;
}

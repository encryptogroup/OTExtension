/**
 \file 		ot-ext-rec.cpp
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
 \brief     XOR Masking
 */

#ifndef XORMASKING_H_
#define XORMASKING_H_

#include "maskingfunction.h"

class XORMasking: public MaskingFunction {
public:
	XORMasking(uint32_t bitlength) {
		init(bitlength);
	}
	;
	XORMasking(uint32_t bitlength, CBitVector& delta) {
		m_vDelta = &delta;
		init(bitlength);
	}
	;
	virtual ~XORMasking() {
	}
	;

	void init(uint32_t bitlength) {
		m_nBitLength = bitlength;
	}

	void Mask(uint32_t progress, uint32_t processedOTs, CBitVector** values, CBitVector* snd_buf, snd_ot_flavor protocol) {

		if (protocol == Snd_OT) {
			snd_buf[0].XORBytes(values[0]->GetArr() + ceil_divide(progress * m_nBitLength, 8), 0, ceil_divide(processedOTs * m_nBitLength, 8));
			snd_buf[1].XORBytes(values[1]->GetArr() + ceil_divide(progress * m_nBitLength, 8), 0, ceil_divide(processedOTs * m_nBitLength, 8));
		} else if (protocol == Snd_C_OT) {
			uint64_t bitPos = progress * m_nBitLength;
			uint64_t length = processedOTs * m_nBitLength;
			uint64_t bytePos = ceil_divide(bitPos, 8);
			values[0]->SetBytes(snd_buf[0].GetArr(), bytePos, ceil_divide(length, 8)); //.SetBits(hash_buf, i*m_nBitLength, m_nBitLength);

			values[1]->SetBits(values[0]->GetArr() + bytePos, bitPos, length);
			values[1]->XORBits(m_vDelta->GetArr() + bytePos, bitPos, length);
			snd_buf[1].XORBits(values[1]->GetArr() + bytePos, 0, length);
		}
		else if (protocol == Snd_R_OT || protocol == Snd_GC_OT) {
			values[0]->SetBytes(snd_buf[0].GetArr(), ceil_divide(progress * m_nBitLength, 8), ceil_divide(processedOTs * m_nBitLength, 8));
			values[1]->SetBytes(snd_buf[1].GetArr(), ceil_divide(progress * m_nBitLength, 8), ceil_divide(processedOTs * m_nBitLength, 8));
		}
	}
	;

	//output already has to contain the masks
	void UnMask(uint32_t progress, uint32_t processedOTs, CBitVector* choices, CBitVector* output, CBitVector* rcv_buf,
			CBitVector* tmpmask, snd_ot_flavor protocol) {
		uint32_t bytelen = bits_in_bytes(m_nBitLength);
		uint64_t gprogress = progress * bytelen;
		uint64_t lim = progress + processedOTs;
		uint64_t offset;

		if (protocol == Snd_OT) {
			if(m_nBitLength & 0x07) {
				gprogress = progress * m_nBitLength;
				offset = PadToMultiple(processedOTs * m_nBitLength, 8);
				output->Copy(tmpmask->GetArr(), bits_in_bytes(gprogress),	bits_in_bytes(offset));
				for (uint32_t u, i = progress,	l = 0; i < lim; i++, gprogress += m_nBitLength, l += m_nBitLength) {
					u = (uint32_t) choices->GetBitNoMask(i);
					output->XORBitsPosOffset(rcv_buf->GetArr(), (u * offset) + l, gprogress, m_nBitLength);
				}
			} else {
				offset = processedOTs * bytelen;
				for (uint32_t u, i = progress, l = 0; i < lim; i++, gprogress += bytelen, l += bytelen) {
					u = (uint32_t) choices->GetBitNoMask(i);
					output->SetXOR(rcv_buf->GetArr() + (u * offset) + l, tmpmask->GetArr() + l, gprogress, bytelen);
				}
			}

		} else if (protocol == Snd_C_OT) {
			if(m_nBitLength & 0x07) {
				gprogress = progress * m_nBitLength;
				offset = PadToMultiple(processedOTs * m_nBitLength, 8);
				//output.Copy(tmpmask.GetArr() + bits_in_bytes(gprogress), bits_in_bytes(gprogress),
				//		bits_in_bytes(offset));
				output->Copy(tmpmask->GetArr(), bits_in_bytes(gprogress), bits_in_bytes(offset));
				for (uint32_t i = progress, l = 0; i < lim; i++, gprogress += m_nBitLength, l += m_nBitLength) {
					if(choices->GetBitNoMask(i)) {
						output->XORBitsPosOffset(rcv_buf->GetArr(), l, gprogress, m_nBitLength);
					}
				}
			} else {
				//output.Copy(tmpmask.GetArr() + gprogress, gprogress, bytelen * processedOTs);
				output->Copy(tmpmask->GetArr(), gprogress, bytelen * processedOTs);
				for (uint32_t i = progress, l = 0; i < lim; i++, l += bytelen, gprogress += bytelen) {
					if (choices->GetBitNoMask(i)) {
						output->XORBytes(rcv_buf->GetArr() + l, gprogress, bytelen);
					}
				}
			}
		} else if (protocol == Snd_R_OT || protocol == Snd_GC_OT) {
			gprogress = bits_in_bytes(progress * m_nBitLength);
			output->Copy(tmpmask->GetArr(), gprogress, bits_in_bytes(processedOTs * m_nBitLength));
		}
	}
	;

	void expandMask(CBitVector* out, BYTE* sbp, uint32_t offset, uint32_t processedOTs, uint32_t bitlength, crypto* crypt) {

		if (bitlength <= AES_KEY_BITS) {
			uint64_t pos = offset * bitlength;
			for (uint32_t i = 0; i < processedOTs; i++, sbp += AES_KEY_BYTES, pos+=bitlength) {
				out->SetBits(sbp, pos, (uint64_t) bitlength);
			}
		} else {
			uint8_t* m_bBuf = (uint8_t*) malloc(AES_BYTES);
			uint8_t* ctr_buf = (uint8_t*) calloc(AES_BYTES, sizeof(uint8_t));
			uint32_t counter = *((uint32_t*) ctr_buf);
			AES_KEY_CTX* tkey = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX));
			//crypt->init_aes_key(tkey, sbp);
			for (uint32_t i = 0, rem; i < processedOTs; i++, sbp += AES_KEY_BYTES) {
				crypt->init_aes_key(tkey, sbp);
				for (counter = 0; counter < bitlength / AES_BITS; counter++) {
					crypt->encrypt(tkey, m_bBuf, ctr_buf, AES_BYTES);
					out->SetBits(m_bBuf, ((uint64_t) offset + i) * bitlength + (counter * AES_BITS), (uint64_t) AES_BITS);
				}
				//the final bits
				if ((rem = bitlength - (counter * AES_BITS)) > 0) {
					crypt->encrypt(tkey, m_bBuf, ctr_buf, AES_BYTES);
					out->SetBits(m_bBuf, ((uint64_t) offset + i) * bitlength + (counter * AES_BITS), (uint64_t) rem);
				}
				crypt->clean_aes_key(tkey);
			}
			free(m_bBuf);
			free(ctr_buf);
			free(tkey);
		}
	}

private:
	CBitVector* m_vDelta;
	uint32_t m_nBitLength;
};

#endif /* XORMASKING_H_ */

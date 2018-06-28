/**
 \file 		baseOT.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		baseOT implementation
 */

#ifndef BASEOT_H_
#define BASEOT_H_

#include "../ENCRYPTO_utils/constants.h"
#include "../ENCRYPTO_utils/typedefs.h"
#include "../ENCRYPTO_utils/crypto/crypto.h"
#include "../ENCRYPTO_utils/crypto/pk-crypto.h"

#ifdef DEBUG_BASE_OT_HASH_RET
#include <iostream>
#endif

class channel;
class CBitVector;


class BaseOT {
public:
	BaseOT(crypto* crypt, field_type ftype) {
		m_cCrypto = crypt;
		m_cPKCrypto = crypt->gen_field(ftype);
	}
	;

	virtual ~BaseOT() { delete m_cPKCrypto; };

	virtual void Sender(uint32_t nSndVals, uint32_t nOTs, channel* chan, uint8_t* ret) = 0;
	virtual void Receiver(uint32_t nSndVals, uint32_t uint32_t, CBitVector* choices, channel* chan, uint8_t* ret) = 0;

protected:

	crypto* m_cCrypto;
	pk_crypto* m_cPKCrypto;

	void hashReturn(uint8_t* ret, uint32_t ret_len, uint8_t* val, uint32_t val_len, uint64_t ctr) {
#ifdef DEBUG_BASE_OT_HASH_RET
		std::cout << ctr << " input : ";
		for(uint32_t i = 0; i < val_len; i++) {
			std::cout << (std::hex) << (uint32_t) val[i];
		}
		std::cout << (std::dec) << std::endl;
#endif
		m_cCrypto->hash_ctr(ret, ret_len, val, val_len, ctr);
#ifdef DEBUG_BASE_OT_HASH_RET
		std::cout << ctr << " output: ";
		for(uint32_t i = 0; i < ret_len; i++) {
			std::cout << (std::hex) << (uint32_t) ret[i];
		}
		std::cout << (std::dec) << std::endl;
#endif
	}

};

#endif /* BASEOT_H_ */

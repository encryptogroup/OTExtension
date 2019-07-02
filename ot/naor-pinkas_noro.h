/**
 \file 		naor-pinkas_noro.h
 \author	
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
 \brief		The Naor-Pinkas OT protocols that does not require a random oracle
 */

#ifndef __Naor_Pinkas_NORO_H_
#define __Naor_Pinkas_NORO_H_

#include "baseOT.h"

class NaorPinkasNoRO : public BaseOT
{

	public:

	~NaorPinkasNoRO(){};
	
	NaorPinkasNoRO(crypto* crypt, field_type ftype) :
		BaseOT(crypt, ftype) {
}
	void Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, BYTE* ret);
	void Sender(uint32_t nSndVals, uint32_t nOTs, channel* chan, BYTE* ret);


	
};
		


#endif

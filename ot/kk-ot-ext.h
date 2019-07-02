/**
 \file 		kk-ot-ext.h
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

#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/codewords.h>
#include <cfloat>

#ifndef KK_OT_EXT_H_
#define KK_OT_EXT_H_

class KKOTExt {
public:
	virtual ~KKOTExt() {
		for(size_t i = 0; i < m_nCodeWordBits; i++) {
			free(m_vCodeWords[i]);
		}
		free(m_vCodeWords);
	}

protected:
	void set_internal_sndvals(uint32_t ext_sndvals, uint32_t bitlen) {
		uint32_t min_int;
		double tmp_cost, min_cost, tmp_log;
		assert(ext_sndvals <= 256);
		min_cost = DBL_MAX;
		for(uint32_t i = ext_sndvals; i <= 256; i*=ext_sndvals) {
			tmp_log = ((double) ceil_log2(i)) / ((double) ceil_log2(ext_sndvals));
			tmp_cost = (256 + i * bitlen * tmp_log) / tmp_log;
			//cout << "cost for i = " << i << ": " << tmp_cost << ", log fact = " << tmp_log << ", min_cost = " << min_cost << endl;
			if(tmp_cost < min_cost) {
				min_int = i;
				min_cost = tmp_cost;
			}
		}
		m_nint_sndvals = min_int;
		//cout << "Internally computing 1-out-of-" << m_nint_sndvals << " for external " << ext_sndvals << endl;
	}
	uint32_t m_nint_sndvals;
	uint64_t** m_vCodeWords;
};

#endif /* KK_OT_EXT_H_ */

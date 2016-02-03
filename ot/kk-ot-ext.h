/*
 * kk-ot-ext.h
 *
 *  Created on: Feb 2, 2016
 *      Author: mzohner
 */

#include "../util/typedefs.h"

#ifndef KK_OT_EXT_H_
#define KK_OT_EXT_H_

class KKOTExt {
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

#ifndef __DOUBLE_EXP_H_
#define __DOUBLE_EXP_H_
#include "../util/typedefs.h"
	#ifdef OTEXT_USE_GMP

#include "baseOT.h"
void powmod2(mpz_t& ret, mpz_t& b1, mpz_t& e1, mpz_t& b2, mpz_t& e2, mpz_t& p);

	#endif
#endif

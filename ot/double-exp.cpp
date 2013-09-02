/*
 * brick.cpp
 *
 *  Created on: April 9, 2013
 *      Author: mzohner
 *
 *  A double exponentiation using Shamirs trick
 */

#include "double-exp.h"
#ifdef OTEXT_USE_GMP
void powmod2(mpz_t& ret, mpz_t& b1, mpz_t& e1, mpz_t& b2, mpz_t& e2, mpz_t& p)
{
	
	int size = max(mpz_sizeinbase(e1, 2), mpz_sizeinbase(e2, 2)); 
	mpz_t prod[4];
	for(int i = 0; i < 4; i++)
		mpz_init(prod[i]);
		
	mpz_set_ui(prod[0], 1);
	mpz_set(prod[1], b1);
	mpz_set(prod[2], b2);
	mpz_mul(prod[3], prod[1], prod[2]);
	mpz_mod(prod[3], prod[3], p);
	
	mpz_set_ui(ret, 1);
	for(int k = size-1; k >= 0; k--)
	{	
		//mpz_mul(ret, ret, ret);
		//mpz_mod(ret, ret, p);
		mpz_powm_ui(ret, ret, 2, p);
		if(mpz_tstbit(e1, k) || mpz_tstbit(e2, k))
		{
			mpz_mul(ret, prod[(mpz_tstbit(e2, k) << 1) + mpz_tstbit(e1, k)], ret);
			mpz_mod(ret, ret, p);	
		}
		
	}
}
#endif

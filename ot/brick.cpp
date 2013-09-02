/*
 * brick.cpp
 *
 *  Created on: Mar 19, 2013
 *      Author: mzohner
 *
 *  A brick exponentiation done by Gilad Asharov
 */

#include "brick.h"

#ifdef OTEXT_USE_GMP
FixedPointExp::FixedPointExp(mpz_t& g, mpz_t& p, int fieldsize)
{
	mpz_init(m_g);
	mpz_init(m_p);
	mpz_set(m_g, g);
	mpz_set(m_p, p);


    m_isInitialized = false;
    m_numberOfElements = fieldsize;
    m_table = NULL;
    init();
}

FixedPointExp::~FixedPointExp() {
  if (m_isInitialized) {
    delete[] m_table;
  }
}

void FixedPointExp::init() {

  m_table = (mpz_t*) malloc(sizeof(mpz_t) * m_numberOfElements);
  for(int i = 0; i < m_numberOfElements; i++)
  {
	  mpz_init(m_table[i]);
  }

 // m_table[0] = m_g;
  mpz_set(m_table[0], m_g);
  for (unsigned u=1; u<m_numberOfElements; ++u) {
	  mpz_mul(m_table[u], m_table[u-1], m_table[u-1]);
	  mpz_mod(m_table[u], m_table[u], m_p);
	  //mpz_powm_ui(m_table[u], m_table[u-1], 2, m_p);
	  //SqrMod(m_table[u], m_table[u-1], m_p);
  }
  m_isInitialized = true;

//   for (unsigned u=0; u<m_numberOfElements; ++u) {
//     cout << "table[" << u << "] = " << m_table[u] << endl;
//     ZZ res;
//     ZZ ex = power_ZZ(2,u);
//     PowerMod(res, m_g, ex, m_p);
//     cout << "    (Should be = " << res << ")" << endl;
//   }
}

void FixedPointExp::powerMod(mpz_t& result, mpz_t& e) {
  mpz_set_ui(result, 1);
  for (unsigned u=0; u<m_numberOfElements; u++) {
    //if (bit(e,u)) {
	  if(mpz_tstbit(e, u))
	  {
		  mpz_mul(result, result, m_table[u]);
		  mpz_mod(result, result, m_p);
	  }
	  //MulMod(result, result, m_table[u], m_p);
   }
}

#endif

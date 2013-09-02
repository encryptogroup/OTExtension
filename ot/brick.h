#ifndef __brick_h__
#define __brick_h__

#include "../util/typedefs.h"

	#ifdef OTEXT_USE_GMP
#include "../util/config.h"

class FixedPointExp {
public:

	FixedPointExp(mpz_t& g, mpz_t& p, int fieldsize);
  ~FixedPointExp();

 public:
  void powerMod(mpz_t& result, mpz_t& e);

 private:
  //create table
  void init();

 private:
  mpz_t m_p;
  mpz_t m_g;
  bool m_isInitialized;
  unsigned m_numberOfElements;
  mpz_t* m_table;
};
	#endif

#endif

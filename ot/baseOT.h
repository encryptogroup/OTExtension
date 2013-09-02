/*
 * baseOT.h
 *
 *  Created on: Mar 20, 2013
 *      Author: mzohner
 */

#ifndef BASEOT_H_
#define BASEOT_H_

#include "../util/typedefs.h"
#include "../util/cbitvector.h"
#include "../util/socket.h"
#include <ctime>
#include "../util/Miracl/ecn.h"
#include "../util/Miracl/big.h"
#include "../util/Miracl/ec2.h"
#include <iostream>
#include <cstring>
#include <fstream>
#include <time.h>
#ifdef OTEXT_USE_GMP
#include "brick.h"
#include "double-exp.h"
#endif


#ifdef OTEXT_USE_GMP
struct security_parameters {
	/* The field size in bytes */
	int field_size;
	mpz_t p;
	mpz_t g;
	mpz_t q;
	gmp_randstate_t	rnd_state;
};

typedef struct security_parameters NPState;

#endif

class BaseOT
{
	public:
		BaseOT(){};
		virtual ~BaseOT(){};

		BOOL Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret)
		{
#ifdef OTEXT_USE_GMP
			if(m_bUseECC)
#endif
				return ReceiverECC(nSndVals, nOTs, choices, sock, ret);
#ifdef OTEXT_USE_GMP
			else
				return ReceiverIFC(nSndVals, nOTs, choices, sock, ret);		
#endif
		};
		
		BOOL Sender(int nSndVals, int nOTs, CSocket& sock, BYTE* ret)
		{
#ifdef OTEXT_USE_GMP
			if(m_bUseECC)
#endif
				return SenderECC(nSndVals, nOTs, sock, ret);		
#ifdef OTEXT_USE_GMP
			else
				return SenderIFC(nSndVals, nOTs, sock, ret);
#endif
		};
		
		BOOL Init(int secparam, BYTE* seed, bool useecc)
		{
#ifdef OTEXT_USE_GMP
			m_bUseECC = useecc;
			if(m_bUseECC)
#endif
				return Miracl_Init(secparam, seed);
#ifdef OTEXT_USE_GMP
			else
				return GMP_Init(secparam, seed);
#endif
		}
		
		BOOL Cleanup()
		{
#ifdef OTEXT_USE_GMP
			if(m_bUseECC)
#endif
				return Miracl_Cleanup();
#ifdef OTEXT_USE_GMP
			else
				return GMP_Cleanup();
#endif
		}

protected: 
#ifdef OTEXT_USE_GMP
		virtual BOOL 			SenderIFC(int nSndVals, int nOTs, CSocket& sock, BYTE* ret) = 0;
		virtual BOOL 			ReceiverIFC(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret) = 0;
#endif
		virtual BOOL 			SenderECC(int nSndVals, int nOTs, CSocket& sock, BYTE* ret) = 0;
		virtual BOOL 			ReceiverECC(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret) = 0;


		int m_SecParam;
		Big *m_BA, *m_BB, *m_BP;
		Big *m_X, *m_Y;

		int m_nM, m_nA, m_nB, m_nC;
		bool m_bUseECC;
		bool m_bUsePrimeField;

#ifdef OTEXT_USE_GMP
		NPState m_NPState;
		BOOL GMP_Init(int secparam, BYTE* seed);
		BOOL GMP_Cleanup();
		// mpz_export does not fill leading zeros, thus a prepending of leading 0s is required
		void mpz_export_padded(BYTE* pBufIdx, int field_size, mpz_t to_export);
#endif
		void hashReturn(BYTE* ret, BYTE* val, int val_len, int ctr);
		
		

		BOOL Miracl_Init(int secparam, BYTE* seed);
		BOOL Miracl_Cleanup();
		BOOL Miracl_InitBrick(ebrick* brick, ECn* point);
		//BOOL Miracl_InitBrick2(ebrick2* brick, ECn* point);
		BOOL Miracl_InitBrick(ebrick2* brick, EC2* point);
		int Miracl_mulbrick(ebrick2* bg, big x, big y, big z);
		int Miracl_mulbrick(ebrick* bg, big x, big y, big z);
		void Miracl_InitPoint(EC2* point, Big x, Big y);
		void Miracl_InitPoint(ECn* point, Big x, Big y);
		void Miracl_brickend(ebrick2* bg);
		void Miracl_brickend(ebrick* bg);

		void PointToByteArray(BYTE* pBufIdx, int field_size, ECn &point);
		void ByteArrayToPoint(ECn *point, int field_size, BYTE* pBufIdx);
		void PointToByteArray(BYTE* pBufIdx, int field_size, EC2 &point);
		void ByteArrayToPoint(EC2 *point, int field_size, BYTE* pBufIdx);
		void SampleRandomPoint(EC2 *point, int field_size);
		void SampleRandomPoint(ECn *point, int field_size);
		
		void printepoint(epoint *point);
};

#endif /* BASEOT_H_ */

/**
 \file 		asharov-lindell.cpp
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



#include "asharov-lindell.h"


/*#ifdef OTEXT_USE_GMP

BOOL AsharovLindell::ReceiverIFC(int nSndVals, int nOTs, CBitVector& choices, CSocket& socket, BYTE* ret)
{
	int nBufSize = nSndVals * m_NPState.field_size * nOTs;
	BYTE* pBuf = new BYTE[nBufSize]; //stores the answer bits of the receiver (d) in the Naor Pinkas Protocol

	mpz_t ztmp, ztmp2, pDec, div;
	mpz_t* h = new mpz_t[nOTs]; //h_i \in G
	mpz_t* beta = new mpz_t[nOTs]; // \beta_i \in Z_q

	mpz_init(ztmp);
	mpz_init(ztmp2);
	mpz_init(pDec);
	mpz_init(div);
	for (int i = 0; i < nOTs; i++) {
		mpz_init(h[i]);
		mpz_init(beta[i]);
	}
	
	mpz_sub_ui(ztmp2, m_NPState.p, 1);
	mpz_cdiv_q(div, ztmp2, m_NPState.q);


	for (int i = 0; i < nOTs; i++) {
		//sample random hi -- sample random element x in Zp, and then compute x^{(p-1)/q} mod p
		do 
		{
			mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size * 8);
			mpz_mod(ztmp2, ztmp, m_NPState.p);
			mpz_powm(h[i], ztmp2, div, m_NPState.p);
		} while(!(mpz_cmp_ui(h[i], (unsigned long int) 1) )  );
		//cout << h[i] << endl;
		//mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size * 8);
		//mpz_mod(ztmp2, ztmp, m_NPState.p);
		//mpz_mul(h[i], ztmp2, ztmp2);
		//mpz_mod(h[i], h[i], m_NPState.p);

		//sample random element betai
		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size * 8);
		mpz_mod(beta[i], ztmp, m_NPState.q);

	}

	BYTE* pBufIdx = pBuf;

	//now, compute hi0, hi1 according to \sigma_i (m_r[i])
	mpz_t h0, h1;
	mpz_init(h0);
	mpz_init(h1);
	FixedPointExp br(m_NPState.g, m_NPState.p, m_NPState.field_size * 8);

	for (int i = 0; i < nOTs; i++) {
		if (!choices.GetBit(i)) { 
			br.powerMod(h0, beta[i]);
			mpz_set(h1, h[i]);
		} else {
			mpz_set(h0, h[i]);
			br.powerMod(h1, beta[i]);
		}

		// put hi0, hi1
		mpz_export_padded(pBufIdx, m_NPState.field_size, h0);
		pBufIdx += m_NPState.field_size; //use next buf positions
		mpz_export_padded(pBufIdx, m_NPState.field_size, h1);
		pBufIdx += m_NPState.field_size; //use next buf positions
	}

	socket.Send(pBuf, nBufSize);
	delete[] pBuf;

	////////////////////////////////////////////////////////////////////////////
	// OT Step 2:
	// Recieve u, (v_i0,v_i1) for every i=1,...,m_nNumberOfInitialOT
	// For every i, compute ki = u^alphai and then xi^\sigma = vi^\sigma XOR KDF(ki^\sigma)
	////////////////////////////////////////////////////////////////////////////

	nBufSize = m_NPState.field_size;
	pBuf = new BYTE[nBufSize];

	socket.Receive(pBuf, nBufSize);

	//reading u
	mpz_t u;
	mpz_init(u);
	mpz_import(u, m_NPState.field_size, 1, sizeof(pBuf[0]), 0, 0, pBuf);

	BYTE* retPtr = ret;
	FixedPointExp ubr(u, m_NPState.p, m_NPState.field_size * 8);
	for (int k = 0; k < nOTs; k++) {
		ubr.powerMod(pDec, beta[k]);
		mpz_export_padded(pBuf, m_NPState.field_size, pDec);

		hashReturn(retPtr, pBuf, m_NPState.field_size, k);
		retPtr += SHA1_BYTES;
	}
	return true;
}


BOOL AsharovLindell::SenderIFC(int nSndVals, int nOTs, CSocket& socket, BYTE* ret)
{
	//buffer for sending u
	int nBufSize = m_NPState.field_size;
	BYTE* pBuf = new BYTE[nBufSize];

	mpz_t alpha, ztmp, u;
	mpz_init(alpha);
	mpz_init(u);
	mpz_init(ztmp);

	//random u
	mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
	mpz_mod(alpha, ztmp, m_NPState.q);
	mpz_powm(u, m_NPState.g, alpha, m_NPState.p);
	mpz_export_padded(pBuf, m_NPState.field_size, u);
	socket.Send(pBuf, nBufSize);

	//====================================================
	// N-P sender: receive pk0
	delete pBuf;
	nBufSize = m_NPState.field_size * nOTs * nSndVals;
	pBuf = new BYTE[nBufSize];
	socket.Receive(pBuf, nBufSize); //receive the d_j's

	mpz_t pH, pK;
	mpz_init(pH);
	mpz_init(pK);

	BYTE* pBufIdx = pBuf;
	BYTE* retPtr = ret;

	for(int k = 0; k < nSndVals * nOTs; k++)
	{
		//mpz_init(k1[k]);
		mpz_import(pH, m_NPState.field_size, 1, sizeof(pBufIdx[0]), 0, 0, pBufIdx);
		mpz_powm(pK, pH, alpha, m_NPState.p);
		mpz_export_padded(pBufIdx, m_NPState.field_size, pK);

		hashReturn(retPtr, pBufIdx, m_NPState.field_size, k/nSndVals);
		pBufIdx += m_NPState.field_size;
		retPtr += SHA1_BYTES;
	}

	return true;
}
#endif*/

void AsharovLindell::Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, BYTE* ret)
{
	/*int coordSize = (m_SecParam+7)/8;//(state.field_size/8) + 4;
	int nBufSize = nSndVals * (coordSize+1) * nOTs;

#ifdef USE_PRIME_FIELD
	ECn g, h0, h1, h[nOTs], u, pDec;
#else
	EC2 g, h0, h1, h[nOTs], u, pDec;
#endif
	Big ztmp, ztmp2, beta[nOTs], xtmp, ytmp;

	BYTE* pBuf = new BYTE[nBufSize]; //stores the answer bits of the receiver (d) in the Naor Pinkas Protocol


	Miracl_InitPoint(&g, *m_X, *m_Y);
#ifdef USE_PRIME_FIELD
	ebrick bg, bu;
#else
	ebrick2 bg, bu;
#endif

	Miracl_InitBrick(&bg, &g);


	for (int i = 0, idx = 0; i < nOTs; i++) {
		//sample random hi -- sample random element x in Zp, and then compute x^2 mod p
		//ztmp = rand(m_SecParam, 2);
		//Miracl_mulbrick(&bg, ztmp.getbig(), xtmp.getbig(), ytmp.getbig());
		//Miracl_InitPoint(h+i, xtmp, ytmp);
		SampleRandomPoint(h+i, m_SecParam);

		beta[i] = rand(m_SecParam, 2);
	}

	BYTE* pBufIdx = pBuf;

	//now, compute hi0, hi1 according to \sigma_i (m_r[i])
	for (int i = 0, idx = 0; i < nOTs; i++) {
		if (!choices.GetBit(i)) 
		{
			Miracl_mulbrick(&bg, beta[i].getbig(), xtmp.getbig(), ytmp.getbig());
			Miracl_InitPoint(&h0, xtmp, ytmp);
			//ecurve_mult(beta[i].getbig(), g.get_point(), h0.get_point());
			h1 = h[i];
		} 
		else 
		{
			h0 = h[i];
			Miracl_mulbrick(&bg, beta[i].getbig(), xtmp.getbig(), ytmp.getbig());
			Miracl_InitPoint(&h1, xtmp, ytmp);//h1 = EC2(xtmp, ytmp);
			//ecurve_mult(beta[i].getbig(), g.get_point(), h1.get_point());

		}

		// put hi0, hi1
		PointToByteArray(pBufIdx, coordSize, h0);
		pBufIdx += coordSize+1; 
		PointToByteArray(pBufIdx, coordSize, h1);
		pBufIdx += coordSize+1; 
	}

	socket.Send(pBuf, nBufSize);
	delete[] pBuf;

	////////////////////////////////////////////////////////////////////////////
	// OT Step 2:
	// Recieve u, (v_i0,v_i1) for every i=1,...,m_nNumberOfInitialOT
	// For every i, compute ki = u^alphai and then xi^\sigma = vi^\sigma XOR KDF(ki^\sigma)
	////////////////////////////////////////////////////////////////////////////

	nBufSize = coordSize +1;
	pBuf = new BYTE[nBufSize];

	socket.Receive(pBuf, nBufSize);

	//reading u
	ByteArrayToPoint(&u, coordSize, pBuf);

	Miracl_InitBrick(&bu, &u);

	BYTE* retPtr = ret;
	for (int k = 0; k < nOTs; k++) 
	{
		//ecurve_mult(beta[k].getbig(), u.get_point(), pDec.get_point());
		Miracl_mulbrick(&bu, beta[k].getbig(), xtmp.getbig(), ytmp.getbig());
		Miracl_InitPoint(&pDec, xtmp, ytmp);//pDec = EC2(xtmp, ytmp);
		PointToByteArray(pBuf, coordSize, pDec);
		hashReturn(retPtr, pBuf, coordSize+1, k);
		retPtr += SHA1_BYTES;
	}
	
	Miracl_brickend(&bu);
	Miracl_brickend(&bg);
	*/
}


void AsharovLindell::Sender(uint32_t nSndVals, uint32_t nOTs, channel* chan, BYTE* ret)
{
/*	//buffer for sending u
	int coordSize = (m_SecParam+7)/8;//(state.field_size/8) + 4;
	int nBufSize = (coordSize+1);
#ifdef USE_PRIME_FIELD
	ECn ztmp, u, g;
#else
	EC2 ztmp, u, g;
#endif
	Big alpha;

	BYTE* pBuf = new BYTE[nBufSize]; 

	Miracl_InitPoint(&g, *m_X, *m_Y);//g = EC2(*m_X, *m_Y);

	//ebrick bg;
	//Miracl_InitBrick(&bg, &g);

	//random u
	alpha = rand(m_SecParam, 2);
	//mul_brick(&bx, alpha.getbig(), xtmp.getbig(), ytmp.getbig());
	//u = ECn(xtmp, ytmp);
	u = g;
	u *= alpha;

	PointToByteArray(pBuf, coordSize, u);
	socket.Send(pBuf, nBufSize);

	//====================================================
	// N-P sender: receive pk0
	delete pBuf;
	nBufSize = (coordSize +1) * nOTs * nSndVals;
	pBuf = new BYTE[nBufSize];
	socket.Receive(pBuf, nBufSize);
	
#ifdef USE_PRIME_FIELD
	ECn pH, pK;
#else
	EC2 pH, pK;
#endif
	BYTE* pBufIdx = pBuf;
	BYTE* retPtr = ret;

	for(int k = 0; k < nSndVals * nOTs; k++)
	{
		ByteArrayToPoint(&pH, coordSize, pBufIdx);
#ifdef USE_PRIME_FIELD
		ecurve_mult(alpha.getbig(), pH.get_point(), pK.get_point());
#else
		ecurve2_mult(alpha.getbig(), pH.get_point(), pK.get_point());
#endif
		PointToByteArray(pBufIdx, coordSize, pK);

		hashReturn(retPtr, pBufIdx, coordSize+1, k/nSndVals);
		pBufIdx += coordSize+1;
		retPtr += SHA1_BYTES;
	}
*/
}


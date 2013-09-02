#include "naor-pinkas.h"

#ifdef OTEXT_USE_GMP

BOOL NaorPinkas::ReceiverIFC(int nSndVals, int nOTs, CBitVector& choices, CSocket& socket, BYTE* ret)
{

	BYTE* pBuf = new BYTE[nOTs*m_NPState.field_size];
	int nBufSize = nSndVals * m_NPState.field_size;

	mpz_t PK_sigma[nOTs], PK0, ztemp, ztmp;
	mpz_t pK[nOTs]; 
	mpz_t pDec[nOTs]; 
	mpz_init(PK0);
	mpz_init(ztemp);
	mpz_init(ztmp);

	FixedPointExp br(m_NPState.g, m_NPState.p, m_NPState.field_size*8);

	for (int k = 0; k < nOTs; k++)
	{
		mpz_init(pK[k]);
		mpz_init(pDec[k]);
		mpz_init(PK_sigma[k]);

		//generate random PK_sigmas
		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
		mpz_mod(pK[k], ztmp, m_NPState.q);
		br.powerMod(PK_sigma[k], pK[k]);
	}

	socket.Receive(pBuf, nBufSize);

	BYTE* pBufIdx = pBuf;

	mpz_t pC[nSndVals];
	for(int u = 0; u < nSndVals; u++)
	{
		mpz_init(pC[u]);
		mpz_import(pC[u], m_NPState.field_size, 1, sizeof(pBuf[0]), 0, 0, pBufIdx);
		pBufIdx += m_NPState.field_size;
	}

	//====================================================
	// N-P receiver: send pk0 
	pBufIdx = pBuf;
	int choice;
	for(int k=0; k<nOTs; k++) 
	{
		choice = choices.GetBit(k);

		if( choice != 0 )
		{
			mpz_invert(ztmp, PK_sigma[k], m_NPState.p); 
			mpz_mul(ztemp, pC[choice], ztmp);
			mpz_mod(PK0, ztemp, m_NPState.p);
		}
		else
		{
			mpz_set(PK0, PK_sigma[k]); 
		}

		mpz_export_padded(pBufIdx, m_NPState.field_size, PK0);
		pBufIdx += m_NPState.field_size; 
	}

	socket.Send(pBuf, nOTs * m_NPState.field_size); 

	delete pBuf;
	pBuf = new BYTE[m_NPState.field_size];
	BYTE* retPtr = ret;

	FixedPointExp pbr (pC[0], m_NPState.p, m_NPState.field_size*8);
	for(int k=0; k<nOTs; k++)
	{
		pbr.powerMod(pDec[k], pK[k]);
		mpz_export_padded(pBuf, m_NPState.field_size, pDec[k]);
		hashReturn(retPtr, pBuf, m_NPState.field_size, k);
		retPtr += SHA1_BYTES;
	}
	return true;
}

BOOL NaorPinkas::SenderIFC(int nSndVals, int nOTs, CSocket& socket, BYTE* ret)
{

	BYTE* pBuf = new BYTE[m_NPState.field_size * nOTs];

	mpz_t pC[nSndVals], pCr[nSndVals], r, ztmp, ztmp2, PK0r, PKr;

	mpz_init(r);
	mpz_init(ztmp);
	mpz_init(ztmp2);
	mpz_init(PK0r);
	mpz_init(PKr);

	for(int u = 0; u < nSndVals; u++)
	{
		mpz_init(pC[u]);
		mpz_init(pCr[u]);
	}

	//random C1
	mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
	mpz_mod(r, ztmp, m_NPState.q);
	mpz_powm(pC[0], m_NPState.g, r, m_NPState.p);

	//random C(i+1)
	for(int u = 1; u < nSndVals; u++)
	{
		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
		mpz_mod(ztmp2, ztmp, m_NPState.q);
		mpz_powm_ui(pC[u], ztmp2, 2, m_NPState.p);
	}

	//====================================================
	// Export the generated C_1-C_nSndVals to a BYTE vector and send them to the receiver
	int nBufSize = nSndVals * m_NPState.field_size;
	BYTE* pBufIdx = pBuf;
	for( int u=0; u<nSndVals; u++ )
	{
		mpz_export_padded(pBufIdx, m_NPState.field_size, pC[u]);
		pBufIdx += m_NPState.field_size;
	}
	socket.Send(pBuf, nBufSize);

	//====================================================
	// compute C^R
	for(int u = 1; u < nSndVals; u++)
	{
		mpz_powm(pCr[u], pC[u], r, m_NPState.p);
	}

	//====================================================
	// N-P sender: receive pk0
	nBufSize = m_NPState.field_size * nOTs;
	socket.Receive(pBuf, nBufSize); //receive the d_j's

	pBufIdx = pBuf;
	mpz_t pPK0[nOTs];
	for(int k = 0; k < nOTs; k++)
	{
		mpz_init(pPK0[k]);
		mpz_import(pPK0[k], m_NPState.field_size, 1, sizeof(pBufIdx[0]), 0, 0, pBufIdx);
		pBufIdx += m_NPState.field_size;
	}

	delete pBuf;
	pBuf = new BYTE[m_NPState.field_size*nSndVals];
	//====================================================
	// Write all nOTs * nSndVals possible values and save hash value to ret
	BYTE* retPtr= ret;
	for(int k=0; k<nOTs; k++ )
	{
		pBufIdx = pBuf;
		for(int u=0; u<nSndVals; u++)
		{
			if( u == 0 )
			{
				// pk0^r
				mpz_powm(PK0r, pPK0[k], r, m_NPState.p);
				mpz_export_padded(pBufIdx, m_NPState.field_size, PK0r);
				mpz_invert(ztmp, PK0r, m_NPState.p);
			}
			else
			{
				// pk^r
				mpz_mul(ztmp2, pCr[u], ztmp);
				mpz_mod(PKr, ztmp2, m_NPState.p);
				mpz_export_padded(pBufIdx, m_NPState.field_size, PKr);
			}
			hashReturn(retPtr, pBufIdx, m_NPState.field_size, k);
			pBufIdx += m_NPState.field_size;
			retPtr += SHA1_BYTES;
		}
	}

	return true;
}
#endif


BOOL NaorPinkas::ReceiverECC(int nSndVals, int nOTs, CBitVector& choices,
		CSocket& socket, BYTE* ret) {

#ifdef USE_PRIME_FIELD
	ECn PK_sigma[nOTs], PK0, ecctmp, invtmp, pDec[nOTs], pC[nSndVals], g;
	ebrick bg, bc;
#else
	EC2 PK_sigma[nOTs], PK0, ecctmp, invtmp, pDec[nOTs], pC[nSndVals], g;
	ebrick2 bg, bc;
#endif
	Big pK[nOTs], bigtmp, x, y, xtmp, ytmp; 

	Miracl_InitPoint(&g, *m_X, *m_Y);//g = EC2(*m_X, *m_Y);

	Miracl_InitBrick(&bg, &g);
	
	int itmp, coordSize = (m_SecParam+7)/8;


	BYTE* pBuf = new BYTE[nOTs * (coordSize + 1)]; 
	int nBufSize = nSndVals * (coordSize + 1);

	//calculate the generator of the group
	for (int k = 0; k < nOTs; k++) {

		pK[k] = rand(m_SecParam, 2);
		
		Miracl_mulbrick(&bg, pK[k].getbig(), xtmp.getbig(), ytmp.getbig());
		Miracl_InitPoint(PK_sigma+k, xtmp, ytmp);//PK_sigma[k] = EC2(xtmp, ytmp);
		
		//PK_sigma[k] = g;
		//PK_sigma[k] *= pK[k];
	}

	socket.Receive(pBuf, nBufSize);

	BYTE* pBufIdx = pBuf;

	for (int u = 0; u < nSndVals; u++) {
		ByteArrayToPoint(pC + u, coordSize, pBufIdx);//mpz_import(pC[u], state.field_size, 1, sizeof(pBuf[0]), 0, 0, pBufIdx);
		pBufIdx += (coordSize + 1);
		//epoint2_norm(pC[u].get_point());
	}
	//cout << "pC[0] = " << pC[0] << endl;
	Miracl_InitBrick(&bc, pC);

	//====================================================
	// N-P receiver: send pk0 
	pBufIdx = pBuf;
	int choice;
	for (int k = 0; k < nOTs; k++) 
	{
		choice = choices.GetBit(k);

		if (choice != 0) {
			PK0 = pC[choice];
			PK0 -= PK_sigma[k];
		} else {
			PK0 = PK_sigma[k];
		}
		//cout << "PK0: " << PK0 << ", PK_sigma: " << PK_sigma[k] << ", choice: " << choice << ", pC[choice: " << pC[choice] << endl;
		PointToByteArray(pBufIdx, coordSize, PK0);
		pBufIdx += (coordSize + 1);
	}

	socket.Send(pBuf, nOTs * (coordSize + 1)); 

	delete [] pBuf;
	pBuf = new BYTE[coordSize+2];
	BYTE* retPtr = ret;

	for (int k = 0; k < nOTs; k++) {
		//pDec[k] = pC[0];
		//pDec[k] *= pK[k];
		Miracl_mulbrick(&bc, pK[k].getbig(), xtmp.getbig(), ytmp.getbig());
		Miracl_InitPoint(pDec+k, xtmp, ytmp);//pDec[k] = EC2(xtmp, ytmp);
		
		PointToByteArray(pBuf, coordSize, pDec[k]);

		hashReturn(retPtr, pBuf, coordSize+1, k);
		retPtr += SHA1_BYTES;
	}

	Miracl_brickend(&bc);//ebrick2_end(&bc);
	Miracl_brickend(&bg);//ebrick2_end(&bg);

	delete [] pBuf;

	return true;
}

BOOL NaorPinkas::SenderECC(int nSndVals, int nOTs, CSocket& socket, BYTE* ret) 
{
	Big alpha, PKr, bigtmp, x, y, xtmp, ytmp;
#ifdef USE_PRIME_FIELD
	ECn pCr[nSndVals], pC[nSndVals], ecctmp, PK0r, invtmp, g;
#else
	EC2 pCr[nSndVals], pC[nSndVals], ecctmp, PK0r, invtmp, g;
#endif
	int itmp, coordSize = (m_SecParam+7)/8;

	BYTE* pBuf = new BYTE[(coordSize + 1) * nOTs];
	Miracl_InitPoint(&g, *m_X, *m_Y);//g = EC2(*m_X, *m_Y);

	//random C1
	alpha = rand(m_SecParam, 2);
	pC[0] = g;
	pC[0] *= alpha;

	//random C(i+1)
	for (int u = 1; u < nSndVals; u++) {
		bigtmp = rand(m_SecParam, 2);
		pC[u] = g;
		pC[u] *= bigtmp;
	}

	//====================================================
	// Export the generated C_1-C_nSndVals to a BYTE vector and send them to the receiver
	int nBufSize = nSndVals * (coordSize + 1);
	BYTE* pBufIdx = pBuf;
	for (int u = 0; u < nSndVals; u++) {
		PointToByteArray(pBufIdx, coordSize, pC[u]);
		pBufIdx += coordSize + 1;
	}
	socket.Send(pBuf, nBufSize);

	//====================================================
	// compute C^R
	for (int u = 1; u < nSndVals; u++) {
#ifdef USE_PRIME_FIELD
		ecurve_mult(alpha.getbig(), pC[u].get_point(), pCr[u].get_point());//mpz_powm(pCr[u], pC[u], alpha, state.p);
#else
		ecurve2_mult(alpha.getbig(), pC[u].get_point(), pCr[u].get_point());//mpz_powm(pCr[u], pC[u], alpha, state.p);
#endif
	}
	//====================================================
	// N-P sender: receive pk0
	nBufSize = (coordSize + 1) * nOTs;
	socket.Receive(pBuf, nBufSize);

	pBufIdx = pBuf;
#ifdef USE_PRIME_FIELD
	ECn pPK0[nOTs];
#else
	EC2 pPK0[nOTs];
#endif
	for (int k = 0; k < nOTs; k++) {
		ByteArrayToPoint(&(pPK0[k]), coordSize, pBufIdx);
		//cout << "pk0[" << k << "]: " << pPK0[k] << endl;
		pBufIdx += (coordSize + 1);
	}

	//====================================================
	// Write all nOTs * nSndVals possible values to ret
	delete [] pBuf;
	pBuf = new BYTE[(coordSize+1) * nSndVals];
	BYTE* retPtr = ret;
	for (int k = 0; k < nOTs; k++)
	{
		pBufIdx = pBuf;
		for (int u = 0; u < nSndVals; u++) {
			if (u == 0) {
				// pk0^r
				//cout << "alpha = " << alpha << ", pk0: " << pPK0[k] << ", pkor: " << PK0r << endl;
#ifdef USE_PRIME_FIELD
				ecurve_mult(alpha.getbig(), pPK0[k].get_point(),PK0r.get_point());
#else
				ecurve2_mult(alpha.getbig(), pPK0[k].get_point(),PK0r.get_point()); 
#endif
				PointToByteArray(pBufIdx, coordSize, PK0r);
				//epoint2_norm(PK0r.get_point());

			} else {
				// pk^r
				ecctmp = pCr[u];
				ecctmp -= PK0r;
				PointToByteArray(pBufIdx, coordSize, ecctmp);
			}
			hashReturn(retPtr, pBufIdx, coordSize+1, k);
			pBufIdx += coordSize+1;//state.field_size;
			retPtr += SHA1_BYTES;
		}

	}

	delete [] pBuf;

	return true;
}



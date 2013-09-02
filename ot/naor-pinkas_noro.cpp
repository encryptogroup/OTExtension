#include "naor-pinkas_noro.h"

#ifdef OTEXT_USE_GMP

BOOL NaorPinkasNoRO::ReceiverIFC(int nSndVals, int nOTs, CBitVector& choices, CSocket& socket, BYTE* ret)
{
	//needs to store x
	int nBufSize = m_NPState.field_size;
	BYTE* pBuf = new BYTE[nBufSize];
	
	
	mpz_t a, b[nOTs], x, y, z0, z1, ztmp, w;
	
	mpz_init(ztmp);
	mpz_init(a);
	mpz_init(x);
	mpz_init(z0);
	mpz_init(z1); 
	mpz_init(w);
	mpz_init(y);
	
	//Fixed Point Exponentiation of the generator g
	FixedPointExp brg(m_NPState.g, m_NPState.p, m_NPState.field_size*8);

	//Fix a and precompute g^a
	mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
	mpz_mod(a, ztmp, m_NPState.q);
	brg.powerMod(x, a);

	//export and send x
	mpz_export_padded(pBuf, m_NPState.field_size, x);
	socket.Send(pBuf, nBufSize);
	
	delete pBuf;
	nBufSize = 3*nOTs*m_NPState.field_size;
	pBuf = new BYTE[nBufSize];
	
	//Fixed Point Exponentiation of x = g^a
	FixedPointExp brx(x, m_NPState.p, m_NPState.field_size*8);

	BYTE* pBufIdx = pBuf;
	for(int k = 0; k < nOTs; k++)
	{
		//randomly sample b and compute y 
		mpz_init(b[k]);
		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
		mpz_mod(b[k], ztmp, m_NPState.q);
		brg.powerMod(y, b[k]);
		
		//compute z0 and z1, depending on the choice bits
		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
		mpz_mod(ztmp, ztmp, m_NPState.q);
		if(!choices.GetBit(k))
		{
			brx.powerMod(z0, b[k]);
			brg.powerMod(z1, ztmp);
			
		} else
		{
			brg.powerMod(z0, ztmp);
			brx.powerMod(z1, b[k]);
		}
		
		//export - first y, then z0, and lastly z1
		mpz_export_padded(pBufIdx, m_NPState.field_size, y);
		pBufIdx += m_NPState.field_size;
		mpz_export_padded(pBufIdx, m_NPState.field_size, z0);
		pBufIdx += m_NPState.field_size; 
		mpz_export_padded(pBufIdx, m_NPState.field_size, z1);
		pBufIdx += m_NPState.field_size;  
	}

	int nRecvBufSize = 2 * nOTs * m_NPState.field_size;
	BYTE* pRecvBuf = new BYTE[nRecvBufSize];
	socket.Receive(pRecvBuf, nRecvBufSize);
		

	socket.Send(pBuf, nBufSize);
	
	BYTE* retPtr = ret;
	pBufIdx = pRecvBuf;
	for(int k = 0; k < nOTs; k++)
	{
		//if the choice bit is zero take the first value, else the second
		mpz_import(w, m_NPState.field_size, 1, sizeof(pBuf[0]), 0, 0, pBufIdx+(choices.GetBit(k) * m_NPState.field_size));
		
		//compute w_sigma^b
		mpz_powm(ztmp, w, b[k], m_NPState.p);
		
		//export result and hash
		mpz_export_padded(pBufIdx, m_NPState.field_size, ztmp);
		hashReturn(retPtr, pBufIdx, m_NPState.field_size, k);
		
		retPtr += SHA1_BYTES;

		//Skip the next two values
		pBufIdx += 2*m_NPState.field_size;
	}

	return true;
}

BOOL NaorPinkasNoRO::SenderIFC(int nSndVals, int nOTs, CSocket& socket, BYTE* ret)
{
	//needs to store x, nOTs*y, nOTs*z0, and nOTs*z1
	int nBufSize = m_NPState.field_size;
	
	BYTE* pBuf = new BYTE[nBufSize];
		
	mpz_t w0, w1, s0[nOTs], s1[nOTs], r0[nOTs], r1[nOTs], R0, R1, x, y, Y, Z0, Z1, z0, z1, ztmp, w;
	
	mpz_init(ztmp);
	mpz_init(x);
	mpz_init(y);
	mpz_init(z0);
	mpz_init(z1); 
	mpz_init(w0);
	mpz_init(w1);
	mpz_init(R0);
	mpz_init(R1);
	mpz_init(Y);
	mpz_init(Z0);
	mpz_init(Z1);
	
	//Fixed Point Exponentiation of the generator g and precompute all possible values
	FixedPointExp brg(m_NPState.g, m_NPState.p, m_NPState.field_size*8);
	
	socket.Receive(pBuf, nBufSize);
	//import x and compute fixed Point Exponentiation of x
	mpz_import(x, m_NPState.field_size, 1, sizeof(pBuf[0]), 0, 0, pBuf);
	FixedPointExp brx(x, m_NPState.p, m_NPState.field_size*8);
	
	delete pBuf;
	nBufSize = 2*nOTs * m_NPState.field_size;
	pBuf = new BYTE[nBufSize];
	
	BYTE* pBufIdx = pBuf;	
	for(int k = 0; k < nOTs; k++)
	{
		mpz_init(r0[k]);
		mpz_init(r1[k]);
		mpz_init(s0[k]);
		mpz_init(s1[k]);

		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
		mpz_mod(s0[k], ztmp, m_NPState.q);
		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
		mpz_mod(s1[k], ztmp, m_NPState.q);
		
		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
		mpz_mod(r0[k], ztmp, m_NPState.q);
		mpz_urandomb(ztmp, m_NPState.rnd_state, m_NPState.field_size*8);
		mpz_mod(r1[k], ztmp, m_NPState.q);
				
		//compute w0 and export it
		brx.powerMod(ztmp, s0[k]);
		brg.powerMod(R0, r0[k]);
		mpz_mul(w0, ztmp, R0);
		mpz_mod(w0, w0, m_NPState.p);
		mpz_export_padded(pBufIdx, m_NPState.field_size, w0);
		pBufIdx += m_NPState.field_size;
				
		//compute w1 and export it		
		brx.powerMod(ztmp, s1[k]);
		brg.powerMod(R1, r1[k]);
		mpz_mul(w1, ztmp, R1);
		mpz_mod(w1, w1, m_NPState.p);
		mpz_export_padded(pBufIdx, m_NPState.field_size, w1);
		pBufIdx += m_NPState.field_size;
	}
	
	//Send data off
	socket.Send(pBuf, nBufSize);
	
	delete pBuf;
	nBufSize = 3*nOTs * m_NPState.field_size;
	pBuf = new BYTE[nBufSize];
	
	//Receive new data
	socket.Receive(pBuf, nBufSize);
	
	BYTE* retPtr = ret;
	pBufIdx = pBuf;
	for(int k = 0; k < nOTs; k++)
	{
		//get y, z0, and z1
		mpz_import(y, m_NPState.field_size, 1, sizeof(pBuf[0]), 0, 0, pBufIdx);
		pBufIdx += m_NPState.field_size;
		mpz_import(z0, m_NPState.field_size, 1, sizeof(pBuf[0]), 0, 0, pBufIdx);
		pBufIdx += m_NPState.field_size;
		mpz_import(z1, m_NPState.field_size, 1, sizeof(pBuf[0]), 0, 0, pBufIdx);
		
		//compute first possible hash 
		mpz_powm(Y, y, r0[k], m_NPState.p);
		mpz_powm(Z0, z0, s0[k], m_NPState.p);
		mpz_mul(ztmp, Y, Z0);
		mpz_mod(ztmp, ztmp, m_NPState.p);
		//powmod2(ztmp, y, r0[k], z0, s0[k], m_NPState.p);
		
		//export result and hash
		mpz_export_padded(pBufIdx, m_NPState.field_size, ztmp);
		hashReturn(retPtr, pBufIdx, m_NPState.field_size, k);
		retPtr += SHA1_BYTES;

		
		//compute second possible hash 
		mpz_powm(Y, y, r1[k], m_NPState.p);
		mpz_powm(Z1, z1, s1[k], m_NPState.p);
		mpz_mul(ztmp, Y, Z1);
		mpz_mod(ztmp, ztmp, m_NPState.p);
		//powmod2(ztmp, y, r1[k], z1, s1[k], m_NPState.p);
		
		//export result and hash
		mpz_export_padded(pBufIdx, m_NPState.field_size, ztmp);
		hashReturn(retPtr, pBufIdx, m_NPState.field_size, k);
		retPtr += SHA1_BYTES;
		
		
		pBufIdx += m_NPState.field_size;
	}


	return true;
}
#endif


BOOL NaorPinkasNoRO::ReceiverECC(int nSndVals, int nOTs, CBitVector& choices, CSocket& socket, BYTE* ret)
{
	//EC2 G;
    	//G=EC2(*m_X,*m_Y);
    	irand((long) 1);//TODO use seed from state!
    	//cout << " g = " << G << endl;
	Big a, b[nOTs], btmp, xtmp, ytmp; 
#ifdef USE_PRIME_FIELD	
	ECn g, x, y, w, z0, z1;
	ebrick bg, bx;
#else
	EC2 g, x, y, w, z0, z1;
	ebrick2 bg, bx;
#endif
	int coordSize = (m_SecParam+7)/8;
	
    	Miracl_InitPoint(&g, *m_X, *m_Y);//g = EC2(*m_X ,*m_Y); 
    	//cout << "G_upd = " << g << endl;
	//g = ECn(*m_X, *m_Y);

	Miracl_InitBrick(&bg, &g);


	//needs to store x
	int nBufSize = (coordSize + 1);
	BYTE* pBuf = new BYTE[nBufSize];
	

	//Fix a and precompute g^a
	a = rand(m_SecParam, 2);

	Miracl_mulbrick(&bg, a.getbig(), xtmp.getbig(), ytmp.getbig());
	Miracl_InitPoint(&x, xtmp, ytmp);//x = EC2(xtmp, ytmp);
	//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, x.get_point());//x.get(xtmp, ytmp);
	//x = g; 
	//x *= a;
	
	//export and send x
	PointToByteArray(pBuf, coordSize, x);
	socket.Send(pBuf, nBufSize);
	
	delete pBuf;
	nBufSize = 3*nOTs*(coordSize + 1);
	pBuf = new BYTE[nBufSize];
	
	Miracl_InitBrick(&bx, &x);

	BYTE* pBufIdx = pBuf;

	for(int k = 0; k < nOTs; k++)
	{
		//randomly sample b and compute y 
		b[k] = rand(m_SecParam, 2);
		Miracl_mulbrick(&bg, b[k].getbig(), xtmp.getbig(), ytmp.getbig());
		Miracl_InitPoint(&y, xtmp, ytmp);//y = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, y.get_point());//y = ECn(xtmp, ytmp);

		//compute z0 and z1, depending on the choice bits
		btmp = rand(m_SecParam, 2);

		if(!choices.GetBit(k))
		{
			Miracl_mulbrick(&bx, b[k].getbig(), xtmp.getbig(), ytmp.getbig());
			Miracl_InitPoint(&z0, xtmp, ytmp);//z0 = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, z0.get_point());//z0 = ECn(xtmp, ytmp);
			Miracl_mulbrick(&bg, btmp.getbig(), xtmp.getbig(), ytmp.getbig());
			Miracl_InitPoint(&z1, xtmp, ytmp);//z1 = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, z1.get_point());//z1 = ECn(xtmp, ytmp);	
		} 
		else
		{
			Miracl_mulbrick(&bg, btmp.getbig(), xtmp.getbig(), ytmp.getbig());
			Miracl_InitPoint(&z1, xtmp, ytmp);//z0 = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, z0.get_point());//z0 = ECn(xtmp, ytmp);//z0.get(xtmp, ytmp);
			Miracl_mulbrick(&bx, b[k].getbig(), xtmp.getbig(), ytmp.getbig());
			Miracl_InitPoint(&z1, xtmp, ytmp);//z1 = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, z1.get_point());//z1 = ECn(xtmp, ytmp);
		}
		
		//export - first y, then z0, and lastly z1
		PointToByteArray(pBufIdx, coordSize, y);
		pBufIdx += (coordSize + 1);
		PointToByteArray(pBufIdx, coordSize, z0);
		pBufIdx += (coordSize + 1); 
		PointToByteArray(pBufIdx, coordSize, z1);
		pBufIdx += (coordSize + 1);  
		//printepoint(g);
		//printepoint(x);
		//cout << "g: " << g << ", x: " << x << ", y: " << y << ", z0: " << z0 << ", z1: " << z1  << endl;
	}

	int nRecvBufSize = 2 * nOTs * (coordSize + 1);
	BYTE* pRecvBuf = new BYTE[nRecvBufSize];
	socket.Receive(pRecvBuf, nRecvBufSize);
		

	socket.Send(pBuf, nBufSize);
	
	BYTE* retPtr = ret;
	pBufIdx = pRecvBuf;
	for(int k = 0; k < nOTs; k++)
	{
		//if the choice bit is zero take the first value, else the second
		ByteArrayToPoint(&w, coordSize, pBufIdx+(choices.GetBit(k) * (coordSize+1)));
		
		//compute w_sigma^b
		//ecurve2_mult(b[k].getbig(), w.get_point(), w.get_point());
		w *= b[k];
		
		//export result and hash
		PointToByteArray(pBufIdx, coordSize, w);
		hashReturn(retPtr, pBufIdx, coordSize+1, k);
		
		retPtr += SHA1_BYTES;

		//Skip the next two values
		pBufIdx += 2*(coordSize+1);

	}
	Miracl_brickend(&bx);//ebrick2_end(&bx);
	Miracl_brickend(&bg);//ebrick2_end(&bg);
	return true;
}




BOOL NaorPinkasNoRO::SenderECC(int nSndVals, int nOTs, CSocket& socket, BYTE* ret) 
{
	Big s0[nOTs], s1[nOTs], r0[nOTs], r1[nOTs], w, xtmp, ytmp;
#ifdef USE_PRIME_FIELD	
	ECn g, w0, w1, R0, R1, x, y, Y, Z0, Z1, z0, z1, ztmp;
	ebrick bg, bx;
#else
	EC2 g, w0, w1, R0, R1, x, y, Y, Z0, Z1, z0, z1, ztmp;
	ebrick2 bg, bx;
#endif


	irand((long) 2);//TODO use seed from state!

	int coordSize = (m_SecParam+7)/8;
//cout << "coordsize = " << coordSize << endl;


	Miracl_InitPoint(&g, *m_X, *m_Y);//g = EC2(*m_X, *m_Y);
	Miracl_InitBrick(&bg, &g);

	//needs to store x, nOTs*y, nOTs*z0, and nOTs*z1
	int nBufSize = coordSize + 1;
	BYTE* pBuf = new BYTE[nBufSize];
		
	socket.Receive(pBuf, nBufSize);
	//import x and compute fixed Point Exponentiation of x
	ByteArrayToPoint(&x, coordSize, pBuf);
	
	Miracl_InitBrick(&bx, &x);
	
	delete pBuf;
	nBufSize = 2*nOTs * (coordSize+1);
	pBuf = new BYTE[nBufSize];
	
	BYTE* pBufIdx = pBuf;	
	for(int k = 0; k < nOTs; k++)
	{
		s0[k] = rand(m_SecParam, 2);
		s1[k] = rand(m_SecParam, 2);
		r0[k] = rand(m_SecParam, 2);
		r1[k] = rand(m_SecParam, 2);
		
		//compute w0 and export it		
		Miracl_mulbrick(&bx, s0[k].getbig(), xtmp.getbig(), ytmp.getbig());
		Miracl_InitPoint(&ztmp, xtmp, ytmp);//ztmp = EC2(xtmp, ytmp);
		Miracl_mulbrick(&bg, r0[k].getbig(), xtmp.getbig(), ytmp.getbig());
		Miracl_InitPoint(&R0, xtmp, ytmp);//R0 = EC2(xtmp, ytmp);
		w0 = ztmp; 
		w0 += R0;
		PointToByteArray(pBufIdx, coordSize, w0);
		pBufIdx += coordSize + 1;
				
		//compute w1 and export it		
		Miracl_mulbrick(&bx, s1[k].getbig(), xtmp.getbig(), ytmp.getbig());
		Miracl_InitPoint(&ztmp, xtmp, ytmp);//ztmp = EC2(xtmp, ytmp);
		Miracl_mulbrick(&bg, r1[k].getbig(), xtmp.getbig(), ytmp.getbig());
		Miracl_InitPoint(&R1, xtmp, ytmp);//R1 = EC2(xtmp, ytmp);
		w1 = ztmp; 
		w1 += R1;
		
		PointToByteArray(pBufIdx, coordSize, w1);
		pBufIdx += coordSize + 1;
	}
	
	//Send data off
	socket.Send(pBuf, nBufSize);
	
	delete pBuf;
	nBufSize = 3*nOTs * (coordSize +1);
	pBuf = new BYTE[nBufSize];
	
	//Receive new data
	socket.Receive(pBuf, nBufSize);
	
	BYTE* retPtr = ret;
	pBufIdx = pBuf;
	for(int k = 0; k < nOTs; k++)
	{
		//get y, z0, and z1
		ByteArrayToPoint(&y, coordSize, pBufIdx);
		pBufIdx += coordSize+1;
		ByteArrayToPoint(&z0, coordSize, pBufIdx);
		pBufIdx += coordSize+1;
		ByteArrayToPoint(&z1, coordSize, pBufIdx);
		pBufIdx += coordSize+1;
		
		//compute first possible hash 
		//cout << "r0: " << r0[k] << ", y: " << y << ", s0: " << s0[k] << ", z0: " << z0 << ", ztmp: " << ztmp << endl;
#ifdef USE_PRIME_FIELD	
		ecurve_mult2(r0[k].getbig(), y.get_point(), s0[k].getbig(), z0.get_point(), ztmp.get_point()); 
#else
		ecurve2_mult2(r0[k].getbig(), y.get_point(), s0[k].getbig(), z0.get_point(), ztmp.get_point()); 
#endif
		//cout << "r0: " << r0[k] << ", y: " << y << ", s0: " << s0[k] << ", z0: " << z0 << ", ztmp: " << ztmp << endl;
		//export result and hash
		PointToByteArray(pBuf, coordSize, ztmp);
		hashReturn(retPtr, pBuf, (coordSize+1), k);
		retPtr += SHA1_BYTES;

		//compute second possible hash 
#ifdef USE_PRIME_FIELD	
		ecurve_mult2(r1[k].getbig(), y.get_point(), s1[k].getbig(), z1.get_point(), ztmp.get_point()); 
#else
		ecurve2_mult2(r1[k].getbig(), y.get_point(), s1[k].getbig(), z1.get_point(), ztmp.get_point()); 
#endif	
		//export result and hash
		PointToByteArray(pBuf, coordSize, ztmp);
		hashReturn(retPtr, pBuf, coordSize+1, k);
		retPtr += SHA1_BYTES;
	}

	Miracl_brickend(&bx);//ebrick2_end(&bx);
	Miracl_brickend(&bg);//ebrick2_end(&bg);

	return true;
}


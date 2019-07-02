/**
 \file 		naor-pinkas_noro.cpp
 \author	
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

#include "naor-pinkas_noro.h"

/*#ifdef OTEXT_USE_GMP

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
#endif*/


void NaorPinkasNoRO::Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector* choices, channel* chan, BYTE* ret)
{
	/*num *a, **b, *btmp; //Big a, b[nOTs], btmp, xtmp, ytmp;
	fe *g, *x, *y, *w, *z0, *z1, *tmp; //EC2 g, x, y, w, z0, z1;
	brickexp *bg, *bx;//ebrick2 bg, bx;
	
	uint32_t hashbytes = m_cCrypto->get_hash_bytes();
	uint32_t febytelen = m_cPKCrypto->fe_byte_size();

	g = m_cPKCrypto->get_generator();//    Miracl_InitPoint(&g, *m_X, *m_Y);//g = EC2(*m_X ,*m_Y);
	b = (num**) malloc(sizeof(num*) * nOTs);
	bg = m_cPKCrypto->get_brick(g); //Miracl_InitBrick(&bg, &g);

	x = m_cPKCrypto->get_fe();
	y = m_cPKCrypto->get_fe();
	w = m_cPKCrypto->get_fe();
	z0 = m_cPKCrypto->get_fe();
	z1 = m_cPKCrypto->get_fe();
	tmp = m_cPKCrypto->get_fe();

	//needs to store x
	uint32_t nBufSize = febytelen; //(coordSize + 1);
	uint8_t* pBuf = (uint8_t*) malloc(nBufSize);
	
	//Fix a and precompute g^a
	a = m_cPKCrypto->get_rnd_num();//rand(m_SecParam, 2);
	bg->pow(x, a);//Miracl_mulbrick(&bg, a.getbig(), xtmp.getbig(), ytmp.getbig());
	//Miracl_InitPoint(&x, xtmp, ytmp);//x = EC2(xtmp, ytmp);
	//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, x.get_point());//x.get(xtmp, ytmp);
	//x = g; 
	//x *= a;
	
	//export and send x
	x->export_to_bytes(pBuf);//PointToByteArray(pBuf, coordSize, x);
	sock->Send(pBuf, nBufSize);
	
	free(pBuf);//delete pBuf;
	nBufSize = 3*nOTs*febytelen;// *(coordSize + 1);
	pBuf = (uint8_t*) malloc(nBufSize);//new BYTE[nBufSize];
	
	bx = m_cPKCrypto->get_brick(x);//Miracl_InitBrick(&bx, &x);

	uint8_t* pBufIdx = pBuf;

	for(uint32_t k = 0; k < nOTs; k++)
	{
		//randomly sample b and compute y 
		b[k] = m_cPKCrypto->get_rnd_num();//rand(m_SecParam, 2);
		bg->pow(y, b[k]);//Miracl_mulbrick(&bg, b[k].getbig(), xtmp.getbig(), ytmp.getbig());
		//Miracl_InitPoint(&y, xtmp, ytmp);//y = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, y.get_point());//y = ECn(xtmp, ytmp);

		//compute z0 and z1, depending on the choice bits
		btmp = m_cPKCrypto->get_rnd_num();//rand(m_SecParam, 2);

		if(!choices.GetBit(k))
		{
			bx->pow(z0, b[k]);//Miracl_mulbrick(&bx, b[k].getbig(), xtmp.getbig(), ytmp.getbig());
			//Miracl_InitPoint(&z0, xtmp, ytmp);//z0 = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, z0.get_point());//z0 = ECn(xtmp, ytmp);
			bg->pow(z1, btmp);//Miracl_mulbrick(&bg, btmp.getbig(), xtmp.getbig(), ytmp.getbig());
			//Miracl_InitPoint(&z1, xtmp, ytmp);//z1 = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, z1.get_point());//z1 = ECn(xtmp, ytmp);
		} 
		else
		{
			bg->pow(z0, btmp);//Miracl_mulbrick(&bg, btmp.getbig(), xtmp.getbig(), ytmp.getbig());
			//Miracl_InitPoint(&z0, xtmp, ytmp);//z0 = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, z0.get_point());//z0 = ECn(xtmp, ytmp);//z0.get(xtmp, ytmp);
			bx->pow(z1, b[k]);//Miracl_mulbrick(&bx, b[k].getbig(), xtmp.getbig(), ytmp.getbig());
			//Miracl_InitPoint(&z1, xtmp, ytmp);//z1 = EC2(xtmp, ytmp);//epoint2_set(xtmp.getbig(), ytmp.getbig(), 0, z1.get_point());//z1 = ECn(xtmp, ytmp);
		}
		
		//export - first y, then z0, and lastly z1
		y->export_to_bytes(pBufIdx);//PointToByteArray(pBufIdx, coordSize, y);
		pBufIdx += febytelen;//(coordSize + 1);
		z0->export_to_bytes(pBufIdx);//PointToByteArray(pBufIdx, coordSize, z0);
		pBufIdx += febytelen;//(coordSize + 1);
		z1->export_to_bytes(pBufIdx);//PointToByteArray(pBufIdx, coordSize, z1);
		pBufIdx += febytelen;//(coordSize + 1);
		//printepoint(g);
		//printepoint(x);
		//cout << "g: " << g << ", x: " << x << ", y: " << y << ", z0: " << z0 << ", z1: " << z1  << endl;
	}

	uint32_t nRecvBufSize = 2 * nOTs * febytelen;//(coordSize + 1);
	uint8_t* pRecvBuf = (uint8_t*) malloc(nRecvBufSize);
	sock->Receive(pRecvBuf, nRecvBufSize);

	sock->Send(pBuf, nBufSize);
	
	uint8_t* retPtr = ret;
	pBufIdx = pRecvBuf;

	uint8_t* cpybuf = (uint8_t*) malloc(febytelen);
	for(uint32_t k = 0; k < nOTs; k++)
	{
		//if the choice bit is zero take the first value, else the second
		tmp->import_from_bytes(pBufIdx+(choices.GetBit(k) * febytelen));//ByteArrayToPoint(&w, coordSize, pBufIdx+(choices.GetBit(k) * (coordSize+1)));
		//w->print();
		//b[k]->print();

		//compute w_sigma^b
		//ecurve2_mult(b[k].getbig(), w.get_point(), w.get_point());
		// *(fe2ec2(w)) *= *(num2Big(b[k]));
		w->set_pow(tmp, b[k]);//w *= b[k];
		//w->print();
		//export result and hash
		w->export_to_bytes(cpybuf);//PointToByteArray(pBufIdx, coordSize, w);
		hashReturn(retPtr, hashbytes, cpybuf, febytelen, k);
		
		retPtr += hashbytes;

		//Skip the next two values
		pBufIdx += 2*febytelen;

	}
	delete bx;//Miracl_brickend(&bx);//ebrick2_end(&bx);
	delete bg;//Miracl_brickend(&bg);//ebrick2_end(&bg);

	free(cpybuf);
	free(pRecvBuf);
	free(pBuf);
	free(b);*/
}




void NaorPinkasNoRO::Sender(uint32_t nSndVals, uint32_t nOTs, channel* chan, BYTE* ret)
{
	/*num **s0, **s1, **r0, **r1, *w;//Big s0[nOTs], s1[nOTs], r0[nOTs], r1[nOTs], w, xtmp, ytmp;
	fe *g, *w0, *w1, *R0, *R1, *x, *y, *Y, *Z0, *Z1, *z0, *z1, *ztmp;//EC2 g, w0, w1, R0, R1, x, y, Y, Z0, Z1, z0, z1, ztmp;
	brickexp *bg, *bx;//ebrick2 bg, bx;

	uint32_t hashbytelen = m_cCrypto->get_hash_bytes();
	uint32_t febytelen = m_cPKCrypto->fe_byte_size();
	//int coordSize = (m_SecParam+7)/8;
//cout << "coordsize = " << coordSize << endl;

	s0 = (num**) malloc(sizeof(num*) * nOTs);
	s1 = (num**) malloc(sizeof(num*) * nOTs);
	r0 = (num**) malloc(sizeof(num*) * nOTs);
	r1 = (num**) malloc(sizeof(num*) * nOTs);


	w0 = m_cPKCrypto->get_fe();
	w1 = m_cPKCrypto->get_fe();
	R0 = m_cPKCrypto->get_fe();
	R1 = m_cPKCrypto->get_fe();
	z0 = m_cPKCrypto->get_fe();
	z1 = m_cPKCrypto->get_fe();
	Z0 = m_cPKCrypto->get_fe();
	Z1 = m_cPKCrypto->get_fe();
	x = m_cPKCrypto->get_fe();
	y = m_cPKCrypto->get_fe();
	Y = m_cPKCrypto->get_fe();
	ztmp = m_cPKCrypto->get_fe();

	g = m_cPKCrypto->get_generator();// Miracl_InitPoint(&g, *m_X, *m_Y);//g = EC2(*m_X, *m_Y);
	bg = m_cPKCrypto->get_brick(g); //Miracl_InitBrick(&bg, &g);

	//needs to store x, nOTs*y, nOTs*z0, and nOTs*z1
	uint32_t nBufSize = febytelen;//coordSize + 1;
	uint8_t* pBuf = (uint8_t*) malloc(nBufSize);
		
	sock->Receive(pBuf, nBufSize);
	//import x and compute fixed Point Exponentiation of x
	x->import_from_bytes(pBuf);//ByteArrayToPoint(&x, coordSize, pBuf);
	
	bx = m_cPKCrypto->get_brick(x);//Miracl_InitBrick(&bx, &x);
	
	free(pBuf);
	nBufSize = 2*nOTs * febytelen;//(coordSize+1);
	pBuf = (uint8_t*) malloc(nBufSize);
	
	uint8_t* pBufIdx = pBuf;

	for(uint32_t k = 0; k < nOTs; k++)
	{
		s0[k] = m_cPKCrypto->get_rnd_num();//rand(m_SecParam, 2);
		s1[k] = m_cPKCrypto->get_rnd_num();//rand(m_SecParam, 2);
		r0[k] = m_cPKCrypto->get_rnd_num();//rand(m_SecParam, 2);
		r1[k] = m_cPKCrypto->get_rnd_num();//rand(m_SecParam, 2);
		
		//compute w0 and export it		
		bx->pow(ztmp, s0[k]);//Miracl_mulbrick(&bx, s0[k].getbig(), xtmp.getbig(), ytmp.getbig());
		//Miracl_InitPoint(&ztmp, xtmp, ytmp);//ztmp = EC2(xtmp, ytmp);
		bg->pow(R0, r0[k]);//Miracl_mulbrick(&bg, r0[k].getbig(), xtmp.getbig(), ytmp.getbig());
		//Miracl_InitPoint(&R0, xtmp, ytmp);//R0 = EC2(xtmp, ytmp);
		w0->set(ztmp);//w0 = ztmp;
		w0->set_mul(w0, R0);//w0 += R0;
		w0->export_to_bytes(pBufIdx);//PointToByteArray(pBufIdx, coordSize, w0);
		pBufIdx += febytelen;//coordSize + 1;
				
		//compute w1 and export it		
		bx->pow(ztmp, s1[k]);//Miracl_mulbrick(&bx, s1[k].getbig(), xtmp.getbig(), ytmp.getbig());
		//Miracl_InitPoint(&ztmp, xtmp, ytmp);//ztmp = EC2(xtmp, ytmp);
		bg->pow(R1, r1[k]);//Miracl_mulbrick(&bg, r1[k].getbig(), xtmp.getbig(), ytmp.getbig());
		//Miracl_InitPoint(&R1, xtmp, ytmp);//R1 = EC2(xtmp, ytmp);
		w1->set(ztmp);//w1 = ztmp;
		w1->set_mul(w1, R1);//w1 += R1;
		
		w1->export_to_bytes(pBufIdx);//PointToByteArray(pBufIdx, coordSize, w1);
		pBufIdx += febytelen;//coordSize + 1;
	}
	
	//Send data off
	sock->Send(pBuf, nBufSize);
	
	free(pBuf);
	nBufSize = 3*nOTs * febytelen;//(coordSize +1);
	pBuf = (uint8_t*) malloc(nBufSize);
	
	//Receive new data
	sock->Receive(pBuf, nBufSize);
	
	uint8_t* retPtr = ret;
	pBufIdx = pBuf;
	for(uint32_t k = 0; k < nOTs; k++)
	{
		//get y, z0, and z1
		y->import_from_bytes(pBufIdx);//ByteArrayToPoint(&y, coordSize, pBufIdx);
		pBufIdx += febytelen;//coordSize+1;
		z0->import_from_bytes(pBufIdx);//ByteArrayToPoint(&z0, coordSize, pBufIdx);
		pBufIdx += febytelen;//coordSize+1;
		z1->import_from_bytes(pBufIdx);//ByteArrayToPoint(&z1, coordSize, pBufIdx);
		pBufIdx += febytelen;//coordSize+1;
		
		//compute first possible hash 
		//cout << "r0: " << r0[k] << ", y: " << y << ", s0: " << s0[k] << ", z0: " << z0 << ", ztmp: " << ztmp << endl;
		ztmp->set_double_pow_mul(y, r0[k], z0, s0[k]);	//ecurve2_mult2(r0[k].getbig(), y.get_point(), s0[k].getbig(), z0.get_point(), ztmp.get_point());
//#endif
		//cout << "r0: " << r0[k] << ", y: " << y << ", s0: " << s0[k] << ", z0: " << z0 << ", ztmp: " << ztmp << endl;
		//export result and hash
		ztmp->export_to_bytes(pBuf);//PointToByteArray(pBuf, coordSize, ztmp);
		hashReturn(retPtr, hashbytelen, pBuf, febytelen, k);
		retPtr += hashbytelen;

		//compute second possible hash 
		ztmp->set_double_pow_mul(y, r1[k], z1, s1[k]);//ecurve2_mult2(r1[k].getbig(), y.get_point(), s1[k].getbig(), z1.get_point(), ztmp.get_point());
		//export result and hash
		ztmp->export_to_bytes(pBuf);//PointToByteArray(pBuf, coordSize, ztmp);
		hashReturn(retPtr, hashbytelen, pBuf, febytelen, k);
		retPtr += hashbytelen;
	}

	delete(bx);////Miracl_brickend(&bx);//ebrick2_end(&bx);
	delete(bg);//Miracl_brickend(&bg);//ebrick2_end(&bg);
	free(pBuf);
	free(s0);
	free(s1);
	free(r0);
	free(r1);*/
}


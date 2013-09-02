#include "ot-extension.h"

BOOL OTExtensionReceiver::receive(int numOTs, int bitlength, CBitVector& choices, CBitVector& ret, BYTE type, int numThreads, MaskingFunction* unmaskfct)
{
		m_nOTs = numOTs;
		m_nBitLength = bitlength;
		m_nChoices = choices;
		m_nRet = ret;
		m_bProtocol = type;
		m_fUnMaskFct = unmaskfct;
		return receive(numThreads);
};

//Initialize and start numThreads OTSenderThread
BOOL OTExtensionReceiver::receive(int numThreads)
{
	if(m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	int internal_numOTs = CEIL_DIVIDE(PadToRegisterSize(m_nOTs), numThreads);

	vector<OTReceiverThread*> rThreads(numThreads); 
	for(int i = 0; i < numThreads; i++)
	{
		rThreads[i] = new OTReceiverThread(i, internal_numOTs, this);
		rThreads[i]->Start();
		
	}
	
	for(int i = 0; i < numThreads; i++)
	{
		rThreads[i]->Wait();
	}
	m_nCounter += m_nOTs;


	for(int i = 0; i < numThreads; i++)
		delete rThreads[i];


#ifdef VERIFY_OT
	verifyOT(m_nOTs);
#endif

	return true;
}



BOOL OTExtensionReceiver::OTReceiverRoutine(int id, int myNumOTs)
{
	int myStartPos = id * myNumOTs;
	int i = myStartPos, nProgress = myStartPos;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	int lim = myStartPos+myNumOTs;

	int processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(myNumOTs, OTEXT_BLOCK_SIZE_BITS));
	int OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;
	CSocket sock = m_nSockets[id];

	//counter variables
	int numblocks = CEIL_DIVIDE(myNumOTs, OTsPerIteration);
	int nSize;

	// The receive buffer
	CBitVector vRcv;
	if(m_bProtocol == G_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	else if(m_bProtocol == C_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength);

	// A temporary part of the T matrix
	CBitVector T(OTEXT_BLOCK_SIZE_BITS * OTsPerIteration);

	// The send buffer
	CBitVector vSnd(NUM_EXECS_NAOR_PINKAS * OTsPerIteration);

	BYTE ctr_buf[AES_BYTES] = {0};
	int* counter = (int*) ctr_buf;
	(*counter) = myStartPos + m_nCounter;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( i < lim )
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(lim-i, OTEXT_BLOCK_SIZE_BITS));
 		OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;
		nSize = NUM_EXECS_NAOR_PINKAS_BYTES * OTsPerIteration;

#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, vSnd, processedOTBlocks, i, ctr_buf);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalMtxTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif

 		sock.Send( vSnd.GetArr(), nSize );
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalSndTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif

 		T.EklundhBitTranspose(OTEXT_BLOCK_SIZE_BITS, OTsPerIteration);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		HashValues(T, i, min(lim-i, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalHshTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		i+=min(lim-i, OTsPerIteration);

 		if(m_bProtocol != R_OT)
 		{
			while(nProgress + NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS < i)
			{
				ReceiveAndProcess(vRcv, id, nProgress, min(lim-nProgress, NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS));
				nProgress += min(lim-nProgress, NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS);
			}
 		}
 		else {
 			nProgress = i;
 		}
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
#endif
 		vSnd.Reset();

	}

	if(m_bProtocol != R_OT)
	{
		while( nProgress < lim )
		{
			ReceiveAndProcess(vRcv, id, nProgress, min(lim-nProgress, NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS));
			nProgress += min(lim-nProgress, NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS);
		}
	}

	T.delCBitVector();
	vSnd.delCBitVector();
	vRcv.delCBitVector();

#ifdef OTTiming
	cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

	cout << "Receiver finished" << endl;

	return TRUE;
}



void OTExtensionReceiver::BuildMatrices(CBitVector& T, CBitVector& SndBuf, int numblocks, int ctr, BYTE* ctr_buf)
{
	int* counter = (int*) ctr_buf;
	int tempctr = (*counter);
	int dummy;
	BYTE* Tptr = T.GetArr();
	BYTE* sndbufptr = SndBuf.GetArr();
	int ctrbyte = ctr/8;
	for(int k = 0; k < NUM_EXECS_NAOR_PINKAS; k++)
	{
		(*counter) = tempctr;
		for(int b = 0; b < numblocks; b++, (*counter)++)
		{
			OTEXT_AES_ENCRYPT(m_vKeySeedMtx + 2*k, Tptr, ctr_buf);
			Tptr+=OTEXT_BLOCK_SIZE_BYTES;

			OTEXT_AES_ENCRYPT(m_vKeySeedMtx + (2*k) + 1, sndbufptr, ctr_buf);
			sndbufptr+=OTEXT_BLOCK_SIZE_BYTES;
		}
		SndBuf.XORBytesReverse(m_nChoices.GetArr()+ctrbyte, k*OTEXT_BLOCK_SIZE_BYTES * numblocks, OTEXT_BLOCK_SIZE_BYTES * numblocks);
	}
	SndBuf.XORBytes(T.GetArr(), 0, OTEXT_BLOCK_SIZE_BYTES*numblocks*NUM_EXECS_NAOR_PINKAS);
}



void OTExtensionReceiver::HashValues(CBitVector& T, int ctr, int processedOTs)
{
	BYTE* Tptr = T.GetArr();
	int numhashiters = CEIL_DIVIDE(m_nBitLength, SHA1_BITS);
	BYTE hash_buf[numhashiters * SHA1_BYTES];
	SHA_BUFFER sha_buf;
	SHA_CTX sha;
	for(int hash_ctr, i = ctr; i < ctr+processedOTs; i++, Tptr+=OTEXT_BLOCK_SIZE_BYTES)
	{
		sha_buf.data = hash_buf;

		for(hash_ctr = 0; hash_ctr < numhashiters; hash_ctr++, sha_buf.data+=SHA1_BYTES)
		{
			OTEXT_HASH_INIT(&sha);
			OTEXT_HASH_UPDATE(&sha, (BYTE*) &i, sizeof(i));
			OTEXT_HASH_UPDATE(&sha, (BYTE*) &hash_ctr, sizeof(hash_ctr));
			OTEXT_HASH_UPDATE(&sha, Tptr, NUM_EXECS_NAOR_PINKAS_BYTES);
			OTEXT_HASH_FINAL(&sha, sha_buf);
		}
		m_nRet.SetBits(hash_buf, i * m_nBitLength, m_nBitLength);
	}
}


void OTExtensionReceiver::ReceiveAndProcess(CBitVector& vRcv, int id, int ctr, int processedOTs)
{

	if(m_bProtocol == G_OT)
	{
		int sock_rcv = CEIL_DIVIDE(processedOTs * m_nBitLength, 8)*2;
		sock_rcv = m_nSockets[id].Receive(vRcv.GetArr(), sock_rcv);
		for(int u, i= 0; i < processedOTs; i++)
		{
			u = (int) m_nChoices.GetBitNoMask(ctr+i);
			m_nRet.XORBitsPosOffset(vRcv.GetArr(), (u*processedOTs*m_nBitLength)+ (i*m_nBitLength), (ctr+i)*m_nBitLength, m_nBitLength);
		}

	}
	else if (m_bProtocol == C_OT)
	{
		int sock_rcv = CEIL_DIVIDE(processedOTs * m_nBitLength, 8);
		m_nSockets[id].Receive(vRcv.GetArr(), sock_rcv);

		//int numIterations = min((sock_rcv<<3) / m_nBitLength, processedOTs);
		m_fUnMaskFct->UnMask(ctr, processedOTs, m_nChoices, m_nRet, vRcv);
		ctr += processedOTs;
	}
}

BOOL OTExtensionReceiver::verifyOT(int NumOTs)
{
	CSocket sock = m_nSockets[0];
	CBitVector vRcvX0(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	CBitVector vRcvX1(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	CBitVector* Xc;
	int processedOTBlocks, OTsPerIteration;
	int bytelen = CEIL_DIVIDE(m_nBitLength, 8);
	BYTE tempXc[bytelen];
	BYTE tempRet[bytelen];
	BYTE resp;
	for(int i = 0; i < NumOTs;)
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(NumOTs-i, OTEXT_BLOCK_SIZE_BITS));
 		//OTsPerIteration = processedOTBlocks * Z_REGISTER_BITS;
		OTsPerIteration = min(processedOTBlocks * OTEXT_BLOCK_SIZE_BITS, NumOTs-i);
		sock.Receive(vRcvX0.GetArr(), CEIL_DIVIDE(m_nBitLength * OTsPerIteration, 8));
		sock.Receive(vRcvX1.GetArr(), CEIL_DIVIDE(m_nBitLength * OTsPerIteration, 8));
		for(int j = 0; j < OTsPerIteration && i < NumOTs; j++, i++)
		{
			if(m_nChoices.GetBitNoMask(i) == 0) Xc = &vRcvX0;
			else Xc = &vRcvX1;

			Xc->GetBits(tempXc, j*m_nBitLength, m_nBitLength);
			m_nRet.GetBits(tempRet, i*m_nBitLength, m_nBitLength);
			for(int k = 0; k < bytelen; k++)
			{
				if(tempXc[k] != tempRet[k])
				{
					cout << "Error at position i = " << i << ", k = " << k << ", with X" << (hex) << (unsigned int) m_nChoices.GetBitNoMask(i)
							<< " = " << (unsigned int) tempXc[k] << " and res = " << (unsigned int) tempRet[k] << (dec) << endl;
					resp = 0x00;
					sock.Send(&resp, 1);
					return false;
				}
			}
		}
		resp = 0x01;
		sock.Send(&resp, 1);
	}
	cout << "OT Verification successful" << endl;
	return true;
}



BOOL OTExtensionSender::send(int numOTs, int bitlength, CBitVector& x0, CBitVector& x1, CBitVector& delta, BYTE type,
		int numThreads, MaskingFunction* maskfct)
{
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_vValues[0] = x0;
	m_vValues[1] = x1;
	m_vDelta = delta;
	m_bProtocol = type;
	m_fMaskFct = maskfct;
	return send(numThreads);
}

//Initialize and start numThreads OTSenderThread
BOOL OTExtensionSender::send(int numThreads)
{
	if(m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	int numOTs = CEIL_DIVIDE(PadToRegisterSize(m_nOTs), numThreads);

	vector<OTSenderThread*> sThreads(numThreads); 

	for(int i = 0; i < numThreads; i++)
	{
		sThreads[i] = new OTSenderThread(i, numOTs, this);
		sThreads[i]->Start();
	}
	
	for(int i = 0; i < numThreads; i++)
	{
		sThreads[i]->Wait();
	}
	m_nCounter += m_nOTs;

	for(int i = 0; i < numThreads; i++)
		delete sThreads[i];

#ifdef VERIFY_OT
	verifyOT(m_nOTs);
#endif


	return true;
}


//BOOL OTsender(int nSndVals, int nOTs, int startpos, CSocket& sock, CBitVector& U, AES_KEY* vKeySeeds, CBitVector* values, BYTE* seed)
BOOL OTExtensionSender::OTSenderRoutine(int id, int myNumOTs)
{
	CSocket sock = m_nSockets[id];
	
	int nProgress;
	int myStartPos = id * myNumOTs; 
	int processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(myNumOTs, OTEXT_BLOCK_SIZE_BITS));
	int OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	int lim = myStartPos+myNumOTs;

	//UINT_64T nToRcvBytes = CEIL_DIVIDE((UINT_64T) NUM_EXECS_NAOR_PINKAS*((UINT_64T)PadToRegisterSize(myNumOTs)), 8);

	// The vector with the received bits
	CBitVector vRcv(NUM_EXECS_NAOR_PINKAS * OTsPerIteration);
		
	// Holds the reply that is sent back to the receiver
	int numsndvals;
	CBitVector* vSnd;

	if(m_bProtocol == G_OT) numsndvals = 2;
	else if (m_bProtocol == C_OT ) numsndvals = 1;
	else numsndvals = 0;

	vSnd = (CBitVector*) malloc(sizeof(CBitVector) * numsndvals);
	for(int i = 0; i < numsndvals; i++)
	{
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Containes the parts of the V matrix
	CBitVector Q(OTEXT_BLOCK_SIZE_BITS * OTsPerIteration);
	
	// A buffer that holds a counting value, required for a faster interaction with the AES calls
	BYTE ctr_buf[AES_BYTES];
	memset(ctr_buf, 0, AES_BYTES);
	int* counter = (int*) ctr_buf;
	counter[0] = myStartPos + m_nCounter;
	
	nProgress = myStartPos;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( nProgress < lim ) //do while there are still transfers missing
	{

		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(lim-nProgress, OTEXT_BLOCK_SIZE_BITS));
		OTsPerIteration = processedOTBlocks * OTEXT_BLOCK_SIZE_BITS;
#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
		sock.Receive(vRcv.GetArr(), NUM_EXECS_NAOR_PINKAS*OTEXT_BLOCK_SIZE_BYTES * processedOTBlocks);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		BuildQMatrix(Q, vRcv, processedOTBlocks, ctr_buf);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalMtxTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		Q.EklundhBitTranspose(OTEXT_BLOCK_SIZE_BITS, OTsPerIteration);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		MaskInputs(Q, vSnd, nProgress, min(lim-nProgress, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalHshTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		ProcessAndSend(vSnd, id, nProgress, min(lim-nProgress, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		nProgress += min(lim-nProgress, OTsPerIteration);
	}

	vRcv.delCBitVector();
	Q.delCBitVector();

	for(int i = 0; i < numsndvals; i++)
		vSnd[i].delCBitVector();
	if(numsndvals > 0)	free(vSnd);

#ifdef OTTiming
	cout << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif


	cout << "Sender finished" << endl;
	return TRUE;
}

void OTExtensionSender::BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, int numblocks, BYTE* ctr_buf)
{
	BYTE* rcvbufptr = RcvBuf.GetArr();
	BYTE* Tptr = T.GetArr();
	int dummy;
	int* counter = (int*) ctr_buf;
	int tempctr = *counter;
	for (int k = 0; k < NUM_EXECS_NAOR_PINKAS; k++, rcvbufptr += (OTEXT_BLOCK_SIZE_BYTES * numblocks))
	{
		*counter = tempctr;
		for(int b = 0; b < numblocks; b++, (*counter)++, Tptr += OTEXT_BLOCK_SIZE_BYTES)
		{
			OTEXT_AES_ENCRYPT(m_vKeySeeds + k, Tptr, ctr_buf);
		}
		if(m_nU.GetBit(k))
		{
			T.XORBytes(rcvbufptr, k*OTEXT_BLOCK_SIZE_BYTES * numblocks, OTEXT_BLOCK_SIZE_BYTES * numblocks);
		}
	}
}

void OTExtensionSender::MaskInputs(CBitVector& Q, CBitVector* SndBuf, int ctr, int processedOTs)
{
	int numhashiters = CEIL_DIVIDE(m_nBitLength, SHA1_BITS);
	SHA_CTX sha, shatmp;
	SHA_BUFFER sha_buf;
	BYTE hash_buf[numhashiters * SHA1_BYTES];
	BYTE* Qptr = Q.GetArr();
	for(int i = ctr, j = 0; j<processedOTs; i++, j++)
	{
		OTEXT_HASH_INIT(&sha);
		OTEXT_HASH_UPDATE(&sha, (BYTE*) &i, sizeof(i));
		shatmp = sha;
		for(int u = 0; u < m_nSndVals; u++)
		{
			if(u == 1)
				Q.XORBytes(m_nU.GetArr(), j * OTEXT_BLOCK_SIZE_BYTES, NUM_EXECS_NAOR_PINKAS_BYTES);

			sha_buf.data = hash_buf;

			for(int hash_ctr = 0; hash_ctr < numhashiters; hash_ctr++, sha_buf.data+=SHA1_BYTES)
			{
				sha = shatmp;
				OTEXT_HASH_UPDATE(&sha, (BYTE*) &hash_ctr, sizeof(hash_ctr));
				OTEXT_HASH_UPDATE(&sha, Q.GetArr()+j * OTEXT_BLOCK_SIZE_BYTES, NUM_EXECS_NAOR_PINKAS_BYTES);
				OTEXT_HASH_FINAL(&sha, sha_buf);
			}
			if(m_bProtocol == G_OT)
			{
				SndBuf[u].SetBits(hash_buf, j* m_nBitLength, m_nBitLength);
				//SndBuf[u].XORBitsPosOffset(m_vValues[u].GetArr(), i * m_nBitLength, (j*2) * m_nBitLength, m_nBitLength);
			}
			else if(m_bProtocol == C_OT)
			{
				if(u == 0)
				{
					m_vValues[0].SetBits(hash_buf, i*m_nBitLength, m_nBitLength);
				}
				else
				{
					SndBuf[0].SetBits(hash_buf, j*m_nBitLength, m_nBitLength);
				}
			}
			else //R_OT
			{
				m_vValues[u].SetBits(hash_buf, i*m_nBitLength, m_nBitLength);
			}
		}
	}
	if(m_bProtocol == G_OT)
	{
		SndBuf[0].XORBytes(m_vValues[0].GetArr() + CEIL_DIVIDE(ctr * m_nBitLength, 8), 0, CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
		SndBuf[1].XORBytes(m_vValues[1].GetArr() + CEIL_DIVIDE(ctr * m_nBitLength, 8), 0, CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
	}

}



void OTExtensionSender::ProcessAndSend(CBitVector* snd_buf, int id, int progress, int processedOTs)
{
	if(m_bProtocol == G_OT)
	{
		m_nSockets[id].Send(snd_buf[0].GetArr(), CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
		m_nSockets[id].Send(snd_buf[1].GetArr(), CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
	}
	else if(m_bProtocol == C_OT)
	{
		m_fMaskFct->Mask(progress, processedOTs, m_vValues, snd_buf[0], m_vDelta);
		m_nSockets[id].Send(snd_buf[0].GetArr(), CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
	}
}

BOOL OTExtensionSender::verifyOT(int NumOTs)
{
	CSocket sock = m_nSockets[0];
	CBitVector vSnd(NUMOTBLOCKS*OTEXT_BLOCK_SIZE_BITS*m_nBitLength);
	int processedOTBlocks, OTsPerIteration;
	int bytelen = CEIL_DIVIDE(m_nBitLength, 8);
	int nSnd;
	BYTE resp;
	for(int i = 0; i < NumOTs;i+=OTsPerIteration)
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(NumOTs-i, OTEXT_BLOCK_SIZE_BITS));
 		OTsPerIteration = min(processedOTBlocks * OTEXT_BLOCK_SIZE_BITS, NumOTs-i);
 		nSnd = CEIL_DIVIDE(OTsPerIteration * m_nBitLength, 8);
 		//cout << "copying " << nSnd << " bytes from " << CEIL_DIVIDE(i*m_nBitLength, 8) << ", for i = " << i << endl;
 		vSnd.Copy(m_vValues[0].GetArr() + CEIL_DIVIDE(i*m_nBitLength, 8), 0, nSnd);
 		sock.Send(vSnd.GetArr(), nSnd);
 		vSnd.Copy(m_vValues[1].GetArr() + CEIL_DIVIDE(i*m_nBitLength, 8), 0, nSnd);
 		sock.Send(vSnd.GetArr(), nSnd);
		sock.Receive(&resp, 1);
		if(resp == 0x00)
		{
			cout << "OT verification unsuccessful" << endl;
			return false;
		}
	}
	cout << "OT Verification successful" << endl;
	return true;
}



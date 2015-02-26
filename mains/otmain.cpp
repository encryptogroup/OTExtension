#include "otmain.h"

#define OTTiming

BOOL Init(crypto* crypt)
{


	m_vSockets = (CSocket*) malloc(sizeof(CSocket) * m_nNumOTThreads);

	if(m_bUseECC)
		bot = new NaorPinkas(crypt, ECC_FIELD);
	else
		bot = new NaorPinkas(crypt, P_FIELD);
	return TRUE;
}

BOOL Cleanup()
{
	for(int i = 0; i < m_nNumOTThreads; i++)
	{
		m_vSockets[i].Close();
	}
	free(m_vSockets);
	return true;
}


BOOL Connect()
{
	BOOL bFail = FALSE;
	LONG lTO = CONNECT_TIMEO_MILISEC;

#ifndef BATCH
	cout << "Connecting to party "<< !m_nPID << ": " << m_nAddr << ", " << m_nPort << endl;
#endif
	for(int k = m_nNumOTThreads-1; k >= 0 ; k--)
	{
		for( int i=0; i<RETRY_CONNECT; i++ )
		{
			if( !m_vSockets[k].Socket() ) 
			{	
				printf("Socket failure: ");
				goto connect_failure; 
			}
			
			if( m_vSockets[k].Connect( m_nAddr, m_nPort, lTO))
			{
				// send pid when connected
				m_vSockets[k].Send( &k, sizeof(int) );
		#ifndef BATCH
				cout << " (" << !m_nPID << ") (" << k << ") connected" << endl;
		#endif
				if(k == 0) 
				{
					//cout << "connected" << endl;
					return TRUE;
				}
				else
				{
					break;
				}
				SleepMiliSec(10);
				m_vSockets[k].Close();
			}
			SleepMiliSec(20);
			if(i+1 == RETRY_CONNECT)
				goto server_not_available;
		}
	}
server_not_available:
	printf("Server not available: ");
connect_failure:
	cout << " (" << !m_nPID << ") connection failed" << endl;
	return FALSE;
}



BOOL Listen()
{
#ifndef BATCH
	cout << "Listening: " << m_nAddr << ":" << m_nPort << ", with size: " << m_nNumOTThreads << endl;
#endif
	if( !m_vSockets[0].Socket() ) 
	{
		goto listen_failure;
	}
	if( !m_vSockets[0].Bind(m_nPort, m_nAddr) )
		goto listen_failure;
	if( !m_vSockets[0].Listen() )
		goto listen_failure;

	for( int i = 0; i<m_nNumOTThreads; i++ ) //twice the actual number, due to double sockets for OT
	{
		CSocket sock;
		//cout << "New round! " << endl;
		if( !m_vSockets[0].Accept(sock) )
		{
			cerr << "Error in accept" << endl;
			goto listen_failure;
		}
					
		UINT threadID;
		sock.Receive(&threadID, sizeof(int));

		if( threadID >= m_nNumOTThreads )
		{
			sock.Close();
			i--;
			continue;
		}

	#ifndef BATCH
		cout <<  " (" << m_nPID <<") (" << threadID << ") connection accepted" << endl;
	#endif
		// locate the socket appropriately
		m_vSockets[threadID].AttachFrom(sock);
		sock.Detach();
	}

#ifndef BATCH
	cout << "Listening finished"  << endl;
#endif
	return TRUE;

listen_failure:
	cout << "Listen failed" << endl;
	return FALSE;
}




void InitOTSender(const char* address, int port, crypto* crypt)
{
	int nSndVals = 2;
#ifdef OTTiming
	timeval np_begin, np_end;
#endif
	m_nPort = (USHORT) port;
	m_nAddr = address;
	vKeySeeds = (BYTE*) malloc(crypt->get_aes_key_bytes()*crypt->get_seclvl().symbits);
	
	//Initialize values
	Init(crypt);
	
	//Server listen
	Listen();
	
#ifdef OTTiming
	gettimeofday(&np_begin, NULL);
#endif	

	PrecomputeNaorPinkasSender(crypt);

#ifdef OTTiming
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif	

	sender = new OTExtensionSender (nSndVals, crypt, m_vSockets, U, vKeySeeds);
}

void InitOTReceiver(const char* address, int port, crypto* crypt)
{
	int nSndVals = 2;
	timeval np_begin, np_end;
	m_nPort = (USHORT) port;
	m_nAddr = address;
	//vKeySeedMtx = (AES_KEY*) malloc(sizeof(AES_KEY)*NUM_EXECS_NAOR_PINKAS * nSndVals);
	vKeySeedMtx = (BYTE*) malloc(crypt->get_aes_key_bytes()*crypt->get_seclvl().symbits * nSndVals);
	//Initialize values
	Init(crypt);
	
	//Client connect
	Connect();
	
#ifdef OTTiming
	gettimeofday(&np_begin, NULL);
#endif

	PrecomputeNaorPinkasReceiver(crypt);
	
#ifdef OTTiming
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif	

	receiver = new OTExtensionReceiver(nSndVals, crypt, m_vSockets, vKeySeedMtx);
}

BOOL PrecomputeNaorPinkasSender(crypto* crypt)
{

	int nSndVals = 2;
	BYTE* pBuf = (BYTE*) malloc(sizeof(BYTE) * crypt->get_seclvl().symbits * crypt->get_hash_bytes());
	
	U.Create(crypt->get_seclvl().symbits, crypt);
	
	bot->Receiver(nSndVals, crypt->get_seclvl().symbits, U, m_vSockets, pBuf);
	
	//Key expansion
	BYTE* pBufIdx = pBuf;
	for(int i=0; i<crypt->get_seclvl().symbits; i++ ) //80 HF calls for the Naor Pinkas protocol
	{
		memcpy(vKeySeeds + i * crypt->get_aes_key_bytes(), pBufIdx, crypt->get_aes_key_bytes());
		pBufIdx+=crypt->get_hash_bytes();
	} 
 	free(pBuf);

 	return true;
}

BOOL PrecomputeNaorPinkasReceiver(crypto* crypt)
{
	int nSndVals = 2;
	
	// Execute NP receiver routine and obtain the key 
	BYTE* pBuf = (BYTE*) malloc(crypt->get_hash_bytes() * crypt->get_seclvl().symbits * nSndVals);

	//=================================================	
	// N-P sender: send: C0 (=g^r), C1, C2, C3 
	bot->Sender(nSndVals, crypt->get_seclvl().symbits, m_vSockets, pBuf);
	
	//Key expansion
	BYTE* pBufIdx = pBuf;
	for(int i=0; i<crypt->get_seclvl().symbits * nSndVals; i++ )
	{
		memcpy(vKeySeedMtx + i * crypt->get_aes_key_bytes(), pBufIdx, crypt->get_aes_key_bytes());
		pBufIdx += crypt->get_hash_bytes();
	}
	
	//free(pBuf);

	return true;
}


BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version, crypto* crypt)
{
	bool success = FALSE;
	int nSndVals = 2; //Perform 1-out-of-2 OT
#ifdef OTTiming
	timeval ot_begin, ot_end;
#endif

	
#ifdef OTTiming
	gettimeofday(&ot_begin, NULL);
#endif
	// Execute OT sender routine 	
	success = sender->send((uint32_t) numOTs, (uint32_t) bitlength, X1, X2, version, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
	gettimeofday(&ot_end, NULL);
	printf("%f\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
	return success;
}

BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version, crypto* crypt)
{
	bool success = FALSE;

#ifdef OTTiming
	timeval ot_begin, ot_end;
	gettimeofday(&ot_begin, NULL);
#endif
	// Execute OT receiver routine 	
	success = receiver->receive(numOTs, bitlength, choices, ret, version, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
	gettimeofday(&ot_end, NULL);
	printf("%f\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
	
	return success;
}


int main(int argc, char** argv)
{
	const char* addr = "127.0.0.1";
	int port = 7766;

	if(argc != 2)
	{
		cout<< "Please call with 0 if acting as server or 1 if acting as client" << endl;
		return 0;
	}

	//Determines whether the program is executed in the sender or receiver role
	m_nPID = atoi(argv[1]);
	cout << "Playing as role: " << m_nPID << endl;
	//the number of OTs that are performed. Has to be initialized to a certain minimum size due to
	int numOTs = 1000000;
	//bitlength of the values that are transferred - NOTE that when bitlength is not 1 or a multiple of 8, the endianness has to be observed
	int bitlength = 80;

	//Use elliptic curve cryptography in the base-OTs
	m_bUseECC = true;
	//The symmetric security parameter (80, 112, 128)
	m_nSecParam = 128;

	//Number of threads that will be used in OT extension
	m_nNumOTThreads = 1;

	//Specifies whether G_OT, C_OT, or R_OT should be used
	BYTE version;

	crypto *crypt = new crypto(m_nSecParam, (uint8_t*) m_vSeed);

	if(m_nPID == SERVER_ID) //Play as OT sender
	{
		InitOTSender(addr, port, crypt);

		CBitVector delta, X1, X2;

		//The masking function with which the values that are sent in the last communication step are processed
		m_fMaskFct = new XORMasking(bitlength, delta);

		//creates delta as an array with "numOTs" entries of "bitlength" bit-values and fills delta with random values
		delta.Create(numOTs, bitlength, crypt);
		//Create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values and resets them to 0
		X1.Create(numOTs, bitlength);
		X1.Reset();
		X2.Create(numOTs, bitlength);
		X2.Reset();

		for(int i = 0; i < numOTs; i++)
		{
			//access and set the i-th element in the bitvectors
			X1.Set(i, 0x55);
			X2.Set(i, 0xAA);
		}

		/* 
		 * G_OT (general OT) obliviously transfers (X1,X2) and omits delta. 
		 * Inputs: 
		 * X1,X2: strings that are obliviously transferred in the OT
		 * delta: is unused in G_OT and does not need to be initialized
		 * Outputs: NONE
		*/
		version = G_OT;
		cout << "Sender performing " << numOTs << " G_OT extensions on " << bitlength << " bit elements" << endl;
		ObliviouslySend(X1, X2, numOTs, bitlength, version, crypt);

		/* 
		 * C_OT (correlated OT) generates X1 at random, obliviously transfers (X1,X1 XOR delta), and outputs X1, X2.  
		 * Inputs: 
		 * delta: string that stores the correlation of the values in C_OT
		 * Outputs: 
		 * X1: is filled with random values. Needs to be a CBitVector of size bitlength*numOTs
		 * X2: is filled with X1 XOR delta. Needs to be a CBitVector of size bitlength*numOTs
		 * 
		 * Note that the correlation (XOR in the example) can be changed in fMaskFct by implementing a different routine.  
		*/
		version = C_OT;
		cout << "Sender performing " << numOTs << " C_OT extensions on " << bitlength << " bit elements" << endl;
		ObliviouslySend(X1, X2, numOTs, bitlength, version, crypt);


		/* 
		 * R_OT (random OT) generates X1 and X2 at random, obliviously transfers (X1,X2), and outputs X1, X2.  
		 * Inputs: 
		 * delta:  is unused in R_OT and does not need to be initialized
		 * Outputs: 
		 * X1: is filled with random values. Needs to be a CBitVector of size bitlength*numOTs
		 * X2: is filled with random values. Needs to be a CBitVector of size bitlength*numOTs
		*/
		version = R_OT;
		cout << "Sender performing " << numOTs << " R_OT extensions on " << bitlength << " bit elements" << endl;
		ObliviouslySend(X1, X2, numOTs, bitlength, version, crypt);

		/*cout << "X1: "<< endl;
		X1.PrintHex();
		cout << "X2: " << endl;
		X2.PrintHex();
		if(version == C_OT)
		{
			cout << "Delta: "<< endl;
			delta.PrintHex();
		}*/
	}
	else //Play as OT receiver
	{
		InitOTReceiver(addr, port, crypt);

		CBitVector choices, response;

		//The masking function with which the values that are sent in the last communication step are processed
		m_fMaskFct = new XORMasking(bitlength);

		//Create the bitvector choices as a bitvector with numOTs entries
		choices.Create(numOTs, crypt);

		//Pre-generate the respose vector for the results
		response.Create(numOTs, bitlength);

		/* 
		 * The inputs of the receiver in G_OT, C_OT and R_OT are the same. The only difference is the version
		 * variable that has to match the version of the sender. 
		*/
		
		version = G_OT;
		cout << "Receiver performing " << numOTs << " G_OT extensions on " << bitlength << " bit elements" << endl;
		ObliviouslyReceive(choices, response, numOTs, bitlength, version, crypt);

		version = C_OT;
		cout << "Receiver performing " << numOTs << " C_OT extensions on " << bitlength << " bit elements" << endl;
		ObliviouslyReceive(choices, response, numOTs, bitlength, version, crypt);

		version = R_OT;
		cout << "Receiver performing " << numOTs << " R_OT extensions on " << bitlength << " bit elements" << endl;
		ObliviouslyReceive(choices, response, numOTs, bitlength, version, crypt);


		/*cout << "Choices: " << endl;
		choices.Print(0, numOTs);
		cout << "Response: " << endl;
		response.PrintHex();*/
	}
	delete crypt;
	Cleanup();

	return 1;
}

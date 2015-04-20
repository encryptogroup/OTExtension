#include "otmain.h"

#define OTTiming

BOOL Init(crypto* crypt)
{
	m_vSocket = new CSocket();//*) malloc(sizeof(CSocket) * m_nNumOTThreads);

	return TRUE;
}

BOOL Cleanup()
{
	delete sndthread;

	delete rcvthread;

	//cout << "Cleaning" << endl;
	delete m_vSocket;
	//cout << "done" << endl;
	return true;
}


BOOL Connect()
{
	bool bFail = FALSE;
	uint64_t lTO = CONNECT_TIMEO_MILISEC;

#ifndef BATCH
	cout << "Connecting to party "<< !m_nPID << ": " << m_nAddr << ", " << m_nPort << endl;
#endif
	for(int k = 0; k >= 0 ; k--)
	{
		for( int i=0; i<RETRY_CONNECT; i++ )
		{
			if( !m_vSocket->Socket() )
			{	
				printf("Socket failure: ");
				goto connect_failure; 
			}
			
			if( m_vSocket->Connect( m_nAddr, m_nPort, lTO))
			{
				// send pid when connected
				m_vSocket->Send( &k, sizeof(int) );
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
				m_vSocket->Close();
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
	if( !m_vSocket->Socket() )
	{
		goto listen_failure;
	}
	if( !m_vSocket->Bind(m_nPort, m_nAddr) )
		goto listen_failure;
	if( !m_vSocket->Listen() )
		goto listen_failure;

	for( int i = 0; i<1; i++ ) //twice the actual number, due to double sockets for OT
	{
		CSocket sock;
		//cout << "New round! " << endl;
		if( !m_vSocket->Accept(sock) )
		{
			cerr << "Error in accept" << endl;
			goto listen_failure;
		}
					
		UINT threadID;
		sock.Receive(&threadID, sizeof(int));

		if( threadID >= 1)
		{
			sock.Close();
			i--;
			continue;
		}

	#ifndef BATCH
		cout <<  " (" << m_nPID <<") (" << threadID << ") connection accepted" << endl;
	#endif
		// locate the socket appropriately
		m_vSocket->AttachFrom(sock);
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
	
	//Initialize values
	Init(crypt);
	
	//Server listen
	Listen();

	sndthread = new SndThread(m_vSocket);
	rcvthread = new RcvThread(m_vSocket);

	rcvthread->Start();
	sndthread->Start();

	switch(m_eProt) {
		case ALSZ: sender = new ALSZOTExtSnd(nSndVals, crypt, rcvthread, sndthread, m_nBaseOTs, m_nChecks); break;
		case IKNP: sender = new IKNPOTExtSnd(nSndVals, crypt, rcvthread, sndthread); break;
		case NNOB: sender = new NNOBOTExtSnd(nSndVals, crypt, rcvthread, sndthread); break;
		default: sender = new ALSZOTExtSnd(nSndVals, crypt, rcvthread, sndthread, m_nBaseOTs, m_nChecks); break;
	}

	if(m_bUseMinEntCorAssumption)
		sender->EnableMinEntCorrRobustness();
	sender->ComputeBaseOTs(m_eFType);
}

void InitOTReceiver(const char* address, int port, crypto* crypt)
{
	int nSndVals = 2;

	m_nPort = (USHORT) port;
	m_nAddr = address;

	//Initialize values
	Init(crypt);
	
	//Client connect
	Connect();

	sndthread = new SndThread(m_vSocket);
	rcvthread = new RcvThread(m_vSocket);
	
	rcvthread->Start();
	sndthread->Start();

	switch(m_eProt) {
		case ALSZ: receiver = new ALSZOTExtRec(nSndVals, crypt, rcvthread, sndthread, m_nBaseOTs, m_nChecks); break;
		case IKNP: receiver = new IKNPOTExtRec(nSndVals, crypt, rcvthread, sndthread); break;
		case NNOB: receiver = new NNOBOTExtRec(nSndVals, crypt, rcvthread, sndthread); break;
		default: receiver = new ALSZOTExtRec(nSndVals, crypt, rcvthread, sndthread, m_nBaseOTs, m_nChecks); break;
	}


	if(m_bUseMinEntCorAssumption)
		receiver->EnableMinEntCorrRobustness();
	receiver->ComputeBaseOTs(m_eFType);
}


BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength,
		snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt)
{
	bool success = FALSE;

	m_vSocket->reset_bytes_sent();
	m_vSocket->reset_bytes_received();
	int nSndVals = 2; //Perform 1-out-of-2 OT
#ifdef OTTiming
	timeval ot_begin, ot_end;
#endif

	
#ifdef OTTiming
	gettimeofday(&ot_begin, NULL);
#endif
	// Execute OT sender routine 	
	success = sender->send((uint32_t) numOTs, (uint32_t) bitlength, X1, X2, stype, rtype, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
	gettimeofday(&ot_end, NULL);
	printf("Time spent:\t%f\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif

	cout << "Sent:\t\t" << m_vSocket->get_bytes_sent() << " bytes" << endl;
	cout << "Received:\t" << m_vSocket->get_bytes_received() <<" bytes" << endl;
	return success;
}

BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength,
		snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt)
{
	bool success = FALSE;

	m_vSocket->reset_bytes_sent();
	m_vSocket->reset_bytes_received();

#ifdef OTTiming
	timeval ot_begin, ot_end;
	gettimeofday(&ot_begin, NULL);
#endif
	// Execute OT receiver routine 	
	success = receiver->receive(numOTs, bitlength, choices, ret, stype, rtype, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
	gettimeofday(&ot_end, NULL);
	printf("Time spent:\t%f\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
	

	cout << "Sent:\t\t" << m_vSocket->get_bytes_sent() << " bytes" << endl;
	cout << "Received:\t" << m_vSocket->get_bytes_received() <<" bytes" << endl;
	return success;
}


int main(int argc, char** argv)
{
	const char* addr = "127.0.0.1";
	int port = 7766;

	if(argc != 2)
	{
		cout << "Please call with 0 if acting as server or 1 if acting as client" << endl;
		return 0;
	}

	//Determines whether the program is executed in the sender or receiver role
	m_nPID = atoi(argv[1]);
	cout << "Playing as role: " << m_nPID << endl;
	assert(m_nPID >= 0 && m_nPID <= 1);
	//the number of OTs that are performed. Has to be initialized to a certain minimum size due to
	uint64_t numOTs = 1000000;
	//bitlength of the values that are transferred - NOTE that when bitlength is not 1 or a multiple of 8, the endianness has to be observed
	uint32_t bitlength = 8;

	//Use elliptic curve cryptography in the base-OTs
	m_eFType = ECC_FIELD;
	//The symmetric security parameter (80, 112, 128)
	uint32_t m_nSecParam = 128;

	//Number of threads that will be used in OT extension
	m_nNumOTThreads = 1;

	//Specifies which OT flavor should be used
	uint32_t stype, rtype;

	crypto *crypt = new crypto(m_nSecParam, (uint8_t*) m_cConstSeed[m_nPID]);

	m_nBaseOTs = 190;
	m_nChecks = 380;

	m_bUseMinEntCorAssumption = false;

	m_eProt = ALSZ;

	if(m_nPID == SERVER_ID) //Play as OT sender
	{
		InitOTSender(addr, port, crypt);

		CBitVector delta, X1, X2;

		//The masking function with which the values that are sent in the last communication step are processed
		m_fMaskFct = new XORMasking(bitlength, delta);

		//creates delta as an array with "numOTs" entries of "bitlength" bit-values and fills delta with random values
		delta.Create(numOTs, bitlength, crypt);

		//Create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values and resets them to 0
		X1.Create(numOTs, bitlength, crypt);
		X2.Create(numOTs, bitlength, crypt);

		for(stype = Snd_OT; stype < Snd_OT_LAST; stype++) {
			for(rtype = Rec_OT; rtype < Rec_OT_LAST; rtype++) {
				cout << "Sender performing " << numOTs << " " << getSndFlavor((snd_ot_flavor) stype) << " / " <<
						getRecFlavor((rec_ot_flavor) rtype) << " extensions on " << bitlength << " bit elements" << endl;
				ObliviouslySend(X1, X2, numOTs, bitlength, (snd_ot_flavor) stype, (rec_ot_flavor) rtype, crypt);
				//X1.PrintHex();
				//X2.PrintHex();
			}
		}
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
		response.Reset();

		/* 
		 * The inputs of the receiver in G_OT, C_OT and R_OT are the same. The only difference is the version
		 * variable that has to match the version of the sender. 
		*/
		for(stype = Snd_OT; stype < Snd_OT_LAST; stype++) {
			for(rtype = Rec_OT; rtype < Rec_OT_LAST; rtype++) {
				cout << "Receiver performing " << numOTs << " " << getSndFlavor((snd_ot_flavor) stype) << " / "
						<< getRecFlavor((rec_ot_flavor)rtype) << " extensions on " << bitlength << " bit elements" << endl;
				ObliviouslyReceive(choices, response, numOTs, bitlength, (snd_ot_flavor) stype, (rec_ot_flavor) rtype, crypt);
				//choices.PrintBinary();
				//response.PrintHex();
			}
		}
	}



	Cleanup();
	delete crypt;

	return 1;
}

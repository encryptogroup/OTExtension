#include "otmain.h"


BOOL Init(crypto* crypt)
{
	m_vSocket = new CSocket();//*) malloc(sizeof(CSocket) * m_nNumOTThreads);

	return TRUE;
}

BOOL Cleanup()
{
	delete sndthread;

	//rcvthread->Wait();

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
		case ALSZ: sender = new ALSZOTExtSnd(crypt, rcvthread, sndthread, m_nBaseOTs, m_nChecks); break;
		case IKNP: sender = new IKNPOTExtSnd(crypt, rcvthread, sndthread); break;
		case NNOB: sender = new NNOBOTExtSnd(crypt, rcvthread, sndthread); break;
		case KK: sender = new KKOTExtSnd(crypt, rcvthread, sndthread); break;
		default: sender = new ALSZOTExtSnd(crypt, rcvthread, sndthread, m_nBaseOTs, m_nChecks); break;
	}

	if(m_bUseMinEntCorAssumption)
		sender->EnableMinEntCorrRobustness();
	sender->ComputeBaseOTs(m_eFType);
}

void InitOTReceiver(const char* address, int port, crypto* crypt)
{
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
		case ALSZ: receiver = new ALSZOTExtRec(crypt, rcvthread, sndthread, m_nBaseOTs, m_nChecks); break;
		case IKNP: receiver = new IKNPOTExtRec(crypt, rcvthread, sndthread); break;
		case NNOB: receiver = new NNOBOTExtRec(crypt, rcvthread, sndthread); break;
		case KK: receiver = new KKOTExtRec(crypt, rcvthread, sndthread); break;
		default: receiver = new ALSZOTExtRec(crypt, rcvthread, sndthread, m_nBaseOTs, m_nChecks); break;
	}


	if(m_bUseMinEntCorAssumption)
		receiver->EnableMinEntCorrRobustness();
	receiver->ComputeBaseOTs(m_eFType);
}


BOOL ObliviouslySend(CBitVector** X, int numOTs, int bitlength, uint32_t nsndvals,
		snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt)
{
	bool success = FALSE;

	m_vSocket->ResetSndCnt();
	m_vSocket->ResetRcvCnt();
	timeval ot_begin, ot_end;

	
	gettimeofday(&ot_begin, NULL);
	// Execute OT sender routine 	
	success = sender->send(numOTs, bitlength, nsndvals, X, stype, rtype, m_nNumOTThreads, m_fMaskFct);
	gettimeofday(&ot_end, NULL);

#ifndef BATCH
	printf("Time spent:\t%f\n", getMillies(ot_begin, ot_end) + rndgentime);
	cout << "Sent:\t\t" << m_vSocket->get_bytes_sent() << " bytes" << endl;
	cout << "Received:\t" << m_vSocket->get_bytes_received() <<" bytes" << endl;
#else
	cout << getMillies(ot_begin, ot_end) + rndgentime << "\t" << m_vSocket->getSndCnt() << "\t" << m_vSocket->getRcvCnt() << endl;
#endif


	return success;
}

BOOL ObliviouslyReceive(CBitVector* choices, CBitVector* ret, int numOTs, int bitlength, uint32_t nsndvals,
		snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt)
{
	bool success = FALSE;

	m_vSocket->ResetSndCnt();
	m_vSocket->ResetRcvCnt();


	timeval ot_begin, ot_end;
	gettimeofday(&ot_begin, NULL);
	// Execute OT receiver routine 	
	success = receiver->receive(numOTs, bitlength, nsndvals, choices, ret, stype, rtype, m_nNumOTThreads, m_fMaskFct);
	gettimeofday(&ot_end, NULL);

#ifndef BATCH
	printf("Time spent:\t%f\n", getMillies(ot_begin, ot_end) + rndgentime);

	cout << "Sent:\t\t" << m_vSocket->get_bytes_sent() << " bytes" << endl;
	cout << "Received:\t" << m_vSocket->get_bytes_received() <<" bytes" << endl;
#else
	cout << getMillies(ot_begin, ot_end) + rndgentime << "\t" << m_vSocket->getSndCnt() << "\t" << m_vSocket->getRcvCnt() << endl;
#endif
	

	return success;
}


int main(int argc, char** argv)
{
	string* addr = new string("127.0.0.1");
	uint16_t port = 7766;

	//Determines whether the program is executed in the sender or receiver role
	m_nPID = atoi(argv[1]);
	//the number of OTs that are performed. Has to be initialized to a certain minimum size due to
	uint64_t numOTs = 1000000;
	//bitlength of the values that are transferred - NOTE that when bitlength is not 1 or a multiple of 8, the endianness has to be observed
	uint32_t bitlength = 8;

	uint32_t runs = 1;

	uint32_t nsndvals = 2;

	//Use elliptic curve cryptography in the base-OTs
	m_eFType = ECC_FIELD;
	//The symmetric security parameter (80, 112, 128)
	uint32_t m_nSecParam = 128;

	//Number of threads that will be used in OT extension
	m_nNumOTThreads = 1;

	//Specifies which OT flavor should be used
	snd_ot_flavor stype = Snd_OT;
	rec_ot_flavor rtype = Rec_OT;


	m_nBaseOTs = 190;
	m_nChecks = 380;

	m_bUseMinEntCorAssumption = false;

	m_eProt = IKNP;

	read_test_options(&argc, &argv, &m_nPID, &numOTs, &bitlength, &m_nSecParam, addr, &port, &m_eProt, &stype, &rtype,
			&m_nNumOTThreads, &m_nBaseOTs, &m_nChecks, &nsndvals, &m_bUseMinEntCorAssumption, &runs);

	/*int32_t read_test_options(int32_t* argcp, char*** argvp, uint32_t* role, uint64_t* numots, uint32_t* bitlen,
			uint32_t* secparam, string* address, uint16_t* port, ot_ext_prot* protocol, snd_ot_flavor* sndflav,
			rec_ot_flavor* rcvflav, uint32_t* nthreads, uint32_t* nbaseots, uint32_t* nchecks, bool* usemecr, uint32_t* runs) {*/

	crypto *crypt = new crypto(m_nSecParam, (uint8_t*) m_cConstSeed[m_nPID]);

	if(m_nPID == SERVER_ID) //Play as OT sender
	{
		InitOTSender(addr->c_str(), port, crypt);

		CBitVector delta;
		CBitVector** X = (CBitVector**) malloc(sizeof(CBitVector*) * nsndvals);


		//The masking function with which the values that are sent in the last communication step are processed
		m_fMaskFct = new XORMasking(bitlength, delta);

		//creates delta as an array with "numOTs" entries of "bitlength" bit-values and fills delta with random values
		delta.Create(numOTs, bitlength, crypt);

		//Create the X values as two arrays with "numOTs" entries of "bitlength" bit-values and resets them to 0
		for(uint32_t i = 0; i < nsndvals; i++) {
			X[i] = new CBitVector();
			X[i]->Create(numOTs, bitlength);
		}

#ifndef BATCH
		cout << getProt(m_eProt) << " Sender performing " << numOTs << " " << getSndFlavor(stype) << " / " <<
				getRecFlavor(rtype) << " extensions on " << bitlength << " bit elements with " <<	m_nNumOTThreads << " threads, " <<
				getFieldType(m_eFType) << " and" << (m_bUseMinEntCorAssumption ? "": " no" ) << " min-ent-corr-robustness " <<
				runs << " times" << endl;
#endif
		for(uint32_t i = 0; i < runs; i++) {
			ObliviouslySend(X, numOTs, bitlength, nsndvals, stype, rtype, crypt);
		}
		/*for(uint32_t i = 0; i < nsndvals; i++) {
			cout << "X" << i << ": ";
			X[i]->PrintHex(0, numOTs);
		}*/
	}
	else //Play as OT receiver
	{
		InitOTReceiver(addr->c_str(), port, crypt);

		CBitVector choices, response;

		//The masking function with which the values that are sent in the last communication step are processed
		m_fMaskFct = new XORMasking(bitlength);

		//Create the bitvector choices as a bitvector with numOTs entries
		choices.Create(numOTs * ceil_log2(nsndvals), crypt);

		//Pre-generate the respose vector for the results
		response.Create(numOTs, bitlength);
		response.Reset();

		/* 
		 * The inputs of the receiver in G_OT, C_OT and R_OT are the same. The only difference is the version
		 * variable that has to match the version of the sender. 
		*/
#ifndef BATCH
		cout << getProt(m_eProt) << " Receiver performing " << numOTs << " " << getSndFlavor(stype) << " / " <<
				getRecFlavor(rtype) << " extensions on " << bitlength << " bit elements with " <<	m_nNumOTThreads << " threads, " <<
				getFieldType(m_eFType) << " and" << (m_bUseMinEntCorAssumption ? "": " no" ) << " min-ent-corr-robustness " <<
				runs << " times" << endl;
#endif
		for(uint32_t i = 0; i < runs; i++) {
			ObliviouslyReceive(&choices, &response, numOTs, bitlength, nsndvals, stype, rtype, crypt);
		}
		/*cout << "C: ";
		choices.PrintHex(0, numOTs);
		cout << "R: ";
		response.PrintHex(0, numOTs);*/

	}

	//Cleanup();
	delete crypt;

	return 1;
}


int32_t read_test_options(int32_t* argcp, char*** argvp, uint32_t* role, uint64_t* numots, uint32_t* bitlen,
		uint32_t* secparam, string* address, uint16_t* port, ot_ext_prot* protocol, snd_ot_flavor* sndflav,
		rec_ot_flavor* rcvflav, uint32_t* nthreads, uint32_t* nbaseots, uint32_t* nchecks, uint32_t* N, bool* usemecr,
		uint32_t* runs) {

	uint32_t int_port = 0, int_prot = 0, int_snd_flav = 0, int_rec_flav = 0;
	bool printhelp = false;

	parsing_ctx options[] = {
			{ (void*) role, T_NUM, 'r', "Role: 0/1", true, false },
			{ (void*) numots, T_NUM, 'n', "Number of OTs, default 10^6", false, false },
			{ (void*) bitlen, T_NUM, 'b', "Bit-length of elements in OTs, default 8", false, false },
			{ (void*) secparam, T_NUM, 's', "Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, 'a', "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, 'p', "Port, default: 7766", false, false },
			{ (void*) &int_prot, T_NUM, 'o', "Protocol, 0: IKNP, 1: ALSZ, 2: NNOB, 3: KK, default: IKNP", false, false },
			{ (void*) &int_snd_flav, T_NUM, 'f', "Sender OT Functionality, 0: OT, 1: C_OT, 2: Snd_R_OT, 3: GC_OT, default: OT", false, false },
			{ (void*) &int_rec_flav, T_NUM, 'v', "Receiver OT Functionality, 0: OT, 1: Rec_R_OT, default: OT", false, false },
			{ (void*) nthreads, T_NUM, 't', "Number of threads, default 1", false, false },
			{ (void*) nbaseots, T_NUM, 'e', "Number of baseots for ALSZ, default 190", false, false },
			{ (void*) nchecks, T_NUM, 'c', "Number of checks for ALSZ, default 380", false, false },
			{ (void*) usemecr, T_FLAG, 'm', "Use Min-Entropy Correlation-Robustness Assumption, default: false", false, false },
			{ (void*) runs, T_NUM, 'u', "Number of repetitions, default: 1", false, false },
			{ (void*) N, T_NUM, 'N', "1-oo-N OT extension. Only works in combination with KK13 and needs to be a power of two, default: 2", false, false },
			{ (void*) &printhelp, T_FLAG, 'h', "Print help", false, false }
	};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	if(printhelp) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(*role < 2);

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	if (int_prot != 0) {
		assert(int_prot > 0 && int_prot < PROT_LAST);
		*protocol = (ot_ext_prot) int_prot;
	}

	if (int_snd_flav != 0) {
		assert(int_snd_flav > 0 && int_snd_flav < Snd_OT_LAST);
		*sndflav = (snd_ot_flavor) int_snd_flav;
	}

	if (int_rec_flav != 0) {
		assert(int_rec_flav > 0 && int_rec_flav < Rec_OT_LAST);
		*rcvflav = (rec_ot_flavor) int_rec_flav;
	}

	if(*N != 2 && (*protocol) != KK) {
		cout << "The N option can only be used in combination with the KK13 OT. Resetting to N=2" << endl;
		*N = 2;
	}

	//delete options;

	return 1;
}

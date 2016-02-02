#include "test.h"

ot_ext_prot test_prots[] = {IKNP, KK, ALSZ, NNOB};
//ot_ext_prot test_prots[] = {IKNP};
snd_ot_flavor test_sflavor[] = {Snd_OT, Snd_C_OT, Snd_GC_OT, Snd_R_OT};
rec_ot_flavor test_rflavor[] = {Rec_OT, Rec_R_OT};
uint64_t test_numots[] = {128, 3215, 100000};
uint64_t test_bitlen[] = {1, 3, 8, 191};
uint32_t test_nthreads[] = {1, 4};
field_type test_ftype[] = {P_FIELD, ECC_FIELD};
bool test_usemecr[] = {false};

BOOL Init()
{
	m_vSocket = new CSocket();

	uint32_t nparams = 8;
	uint32_t* ntestparams = (uint32_t*) malloc(nparams * sizeof(uint32_t));
	//uint32_t* ctr = (uint32_t) calloc(nparams, sizeof(uint32_t));

	ntestparams[0] = sizeof(test_prots)/sizeof(ot_ext_prot);
	ntestparams[1] = sizeof(test_sflavor)/sizeof(snd_ot_flavor);
	ntestparams[2] = sizeof(test_rflavor)/sizeof(rec_ot_flavor);
	ntestparams[3] = sizeof(test_numots)/sizeof(uint64_t);
	ntestparams[4] = sizeof(test_bitlen)/sizeof(uint64_t);
	ntestparams[5] = sizeof(test_nthreads)/sizeof(uint32_t);
	ntestparams[6] = sizeof(test_usemecr)/sizeof(bool);
	ntestparams[7] = sizeof(test_ftype)/sizeof(field_type);


	m_nTests = 1;
	gen_tests = 0;
	for(uint32_t i = 0; i < nparams; i++) {
		m_nTests *= ntestparams[i];
	}
	//cout << "ntests = " << m_nTests << endl;
	//Init test options
	tests = (test_options*) malloc(sizeof(test_options) * (m_nTests+1));
	test_options* test_ptr = tests;
	recursive_assign_test_params(ntestparams, 0, &test_ptr, nparams);

	free(ntestparams);

	return TRUE;
}

void recursive_assign_test_params(uint32_t* max, uint32_t depth, test_options** tops, uint32_t max_depth) {

	for(uint32_t i = 0; i < max[depth]; i++) {
		assign_param(i, depth, *tops);
		if(depth == max_depth-1) {
			memcpy((*tops)+1, *tops, sizeof(test_options));
			(*tops)++;
			//cout << "another " << gen_tests++ << ", total: " << m_nTests << endl;
		} else {
			recursive_assign_test_params(max, depth+1, tops, max_depth);
		}
	}
}

void assign_param(uint32_t ctr, uint32_t depth, test_options* tops) {
	//tops->ftype = test_ftype[ctr % 2];
	//tops->usemecr = test_ftype[ctr % (sizeof(test_usemecr)/sizeof(bool))];
	switch(depth) {
	case 0: tops->prot = test_prots[ctr]; break;
	case 1: tops->sflavor = test_sflavor[ctr]; break;
	case 2: tops->rflavor = test_rflavor[ctr]; break;
	case 3: tops->numots = test_numots[ctr]; break;
	case 4: tops->bitlen = test_bitlen[ctr]; break;
	case 5: tops->nthreads = test_nthreads[ctr]; break;
	case 6: tops->usemecr = test_usemecr[ctr]; break;
	case 7: tops->ftype = test_ftype[ctr]; break;

	default: cerr << "Test case not recognized, abort" << endl; exit(0);
	}
}

BOOL Cleanup()
{
	delete sndthread;
	delete rcvthread;
	delete m_vSocket;

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
	cout << "Listening: " << m_nAddr << ":" << m_nPort  << endl;
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




void InitSender(const char* address, int port) {
	m_nPort = (USHORT) port;
	m_nAddr = address;
	
	//Initialize values
	Init();
	
	//Server listen
	Listen();

	sndthread = new SndThread(m_vSocket);
	rcvthread = new RcvThread(m_vSocket);

	sndthread->Start();
	rcvthread->Start();
}

void InitReceiver(const char* address, int port) {
	m_nPort = (USHORT) port;
	m_nAddr = address;

	//Initialize values
	Init();
	
	//Client connect
	Connect();

	sndthread = new SndThread(m_vSocket);
	rcvthread = new RcvThread(m_vSocket);
	
	sndthread->Start();
	rcvthread->Start();
}


OTExtSnd* InitOTExtSnd(ot_ext_prot m_eProt, uint32_t nbaseots, uint32_t nchecks, bool enablemecr, field_type ftype, crypto* crypt) {
	uint32_t nsndvals = 2;
	OTExtSnd* sender;
	switch(m_eProt) {
		case ALSZ: sender = new ALSZOTExtSnd(crypt, rcvthread, sndthread, nbaseots, nchecks); break;
		case IKNP: sender = new IKNPOTExtSnd(crypt, rcvthread, sndthread); break;
		case NNOB: sender = new NNOBOTExtSnd(crypt, rcvthread, sndthread); break;
		default: sender = new ALSZOTExtSnd(crypt, rcvthread, sndthread, nbaseots, nchecks); break;
	}

	if(enablemecr)
		sender->EnableMinEntCorrRobustness();
	sender->ComputeBaseOTs(ftype);
	return sender;
}


OTExtRec* InitOTExtRec(ot_ext_prot m_eProt, uint32_t nbaseots, uint32_t nchecks, bool enablemecr, field_type ftype, crypto* crypt) {
	uint32_t nsndvals = 2;
	OTExtRec* receiver;
	switch(m_eProt) {
		case ALSZ: receiver = new ALSZOTExtRec(crypt, rcvthread, sndthread, nbaseots, nchecks); break;
		case IKNP: receiver = new IKNPOTExtRec(crypt, rcvthread, sndthread); break;
		case NNOB: receiver = new NNOBOTExtRec(crypt, rcvthread, sndthread); break;
		default: receiver = new ALSZOTExtRec(crypt, rcvthread, sndthread, nbaseots, nchecks); break;
	}

	if(enablemecr)
		receiver->EnableMinEntCorrRobustness();
	receiver->ComputeBaseOTs(ftype);
	return receiver;
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

	//The symmetric security parameter (80, 112, 128)
	uint32_t m_nSecParam = 128;

	crypto *crypt = new crypto(m_nSecParam, (uint8_t*)  m_cConstSeed[m_nPID]);

	uint32_t m_nBaseOTs = 190;
	uint32_t m_nChecks = 380;

	if(m_nPID == SERVER_ID) //Play as OT sender
	{
		InitSender(addr, port);

		OTExtSnd* sender = NULL;
		for(uint32_t i = 0; i < m_nTests; i++) {
			sender = InitOTExtSnd(tests[i].prot, m_nBaseOTs, m_nChecks, tests[i].usemecr, tests[i].ftype, crypt);

			cout << "Test " << i << ": " << getProt(tests[i].prot) << " Sender " << tests[i].numots << " " <<
					getSndFlavor(tests[i].sflavor) << " / " << getRecFlavor(tests[i].rflavor) << " on " <<
					tests[i].bitlen << " bits with " <<	tests[i].nthreads << " threads, " <<
					getFieldType(tests[i].ftype) << " and" << (tests[i].usemecr ? "": " no" ) << " MECR"<< endl;

			run_test_sender(tests[i].numots, tests[i].bitlen, tests[i].sflavor, tests[i].rflavor, tests[i].nthreads, crypt, sender);

			delete sender;
		}
	}
	else //Play as OT receiver
	{
		InitReceiver(addr, port);

		OTExtRec* receiver = NULL;
		for(uint32_t i = 0; i < m_nTests; i++) {
			receiver = InitOTExtRec(tests[i].prot, m_nBaseOTs, m_nChecks, tests[i].usemecr, tests[i].ftype, crypt);

			cout << "Test " << i << ": " << getProt(tests[i].prot) << " Receiver " << tests[i].numots << " " <<
					getSndFlavor(tests[i].sflavor) << " / " << getRecFlavor(tests[i].rflavor) << " on " <<
					tests[i].bitlen << " bits with " <<	tests[i].nthreads << " threads, " <<
					getFieldType(tests[i].ftype) << " and" << (tests[i].usemecr ? "": " no" ) << " MECR"<< endl;

			run_test_receiver(tests[i].numots, tests[i].bitlen, tests[i].sflavor, tests[i].rflavor, tests[i].nthreads, crypt, receiver);

			delete receiver;
		}

	}

	Cleanup();
	delete crypt;

	return 1;
}


void run_test_sender(uint32_t numots, uint32_t bitlength, snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numthreads,
		crypto* crypt, OTExtSnd* sender) {
	CBitVector delta;
	uint32_t nsndvals = 2;
	CBitVector** X = (CBitVector**) malloc(sizeof(CBitVector*) * nsndvals);

	//The masking function with which the values that are sent in the last communication step are processed
	XORMasking* m_fMaskFct = new XORMasking(bitlength, delta);

	//creates delta as an array with "numOTs" entries of "bitlength" bit-values and fills delta with random values
	delta.Create(numots, bitlength, crypt);

	//Create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values and resets them to 0
	//X1.Create(numots, bitlength, crypt);
	//X2.Create(numots, bitlength, crypt);
	for(uint32_t i = 0; i < nsndvals; i++) {
		X[i] = new CBitVector();
		X[i]->Create(numots, bitlength, crypt);
	}

	sender->send(numots, bitlength, nsndvals, X, stype, rtype, numthreads, m_fMaskFct);

	//X1.PrintHex();
	//X2.PrintHex();

	for(uint32_t i = 0; i < nsndvals; i++) {
		X[i]->delCBitVector();
	}
	//free(X);
	//X1.delCBitVector();
	//X2.delCBitVector();
	delta.delCBitVector();
	delete m_fMaskFct;
}


void run_test_receiver(uint32_t numots, uint32_t bitlength, snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numthreads,
		crypto* crypt, OTExtRec* receiver) {
	CBitVector choices, response;
	uint32_t nsndvals = 2;
	//The masking function with which the values that are sent in the last communication step are processed
	XORMasking* m_fMaskFct = new XORMasking(bitlength);

	//Create the bitvector choices as a bitvector with numOTs entries
	choices.Create(numots, crypt);

	//Pre-generate the respose vector for the results
	response.Create(numots, bitlength);
	response.Reset();

	/*
	 * The inputs of the receiver in G_OT, C_OT and R_OT are the same. The only difference is the version
	 * variable that has to match the version of the sender.
	*/

	receiver->receive(numots, bitlength, nsndvals, &choices, &response, stype, rtype, numthreads, m_fMaskFct);
	delete m_fMaskFct;
	choices.delCBitVector();
	response.delCBitVector();
}

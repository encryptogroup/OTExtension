#include "test.h"
#include <cstdlib>
#include <iostream>
#include <ENCRYPTO_utils/connection.h>

//ot_ext_prot test_prots[] = {IKNP, KK, ALSZ, NNOB};
ot_ext_prot test_prots[] = {IKNP};
snd_ot_flavor test_sflavor[] = {Snd_OT, Snd_C_OT, Snd_GC_OT, Snd_R_OT};
rec_ot_flavor test_rflavor[] = {Rec_OT, Rec_R_OT};
uint64_t test_numots[] = {128, 3215, 100000};
uint64_t test_bitlen[] = {1, 3, 8, 191};
uint32_t test_nthreads[] = {1, 4};
field_type test_ftype[] = {P_FIELD, ECC_FIELD};
bool test_usemecr[] = {false};

BOOL Init()
{
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
	//std::cout << "ntests = " << m_nTests << std::endl;
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
			//std::cout << "another " << gen_tests++ << ", total: " << m_nTests << std::endl;
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

	default: std::cerr << "Test case not recognized, abort" << std::endl; std::exit(EXIT_FAILURE);
	}
}

BOOL Cleanup()
{
	delete sndthread;
	delete rcvthread;

	return true;
}


void InitSender(const std::string& address, const int port, CLock *glock) {
	m_nPort = (uint16_t) port;
	m_nAddr = &address;
	
	//Initialize values
	Init();
	
	//Server listen
	m_Socket = Listen(address, port);
	if (!m_Socket) {
		std::cerr << "Listen failed on " << address << ":" << port << "\n";
		std::exit(1);
	}

	sndthread = new SndThread(m_Socket.get(), glock);
	rcvthread = new RcvThread(m_Socket.get(), glock);

	sndthread->Start();
	rcvthread->Start();
}

void InitReceiver(const std::string& address, const int port, CLock *glock) {
	m_nPort = (uint16_t) port;
	m_nAddr = &address;

	//Initialize values
	Init();
	
	//Client connect
	m_Socket = Connect(address, port);
	if (!m_Socket) {
		std::cerr << "Connect failed on " << address << ":" << port << "\n";
		std::exit(1);
	}

	sndthread = new SndThread(m_Socket.get(), glock);
	rcvthread = new RcvThread(m_Socket.get(), glock);
	
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
	std::string addr = "127.0.0.1";
	int port = 7766;

	if(argc != 2)
	{
		std::cout << "Please call with 0 if acting as server or 1 if acting as client" << std::endl;
		return EXIT_FAILURE;
	}

	//Determines whether the program is executed in the sender or receiver role
	m_nPID = atoi(argv[1]);
	std::cout << "Playing as role: " << m_nPID << std::endl;
	assert(m_nPID >= 0 && m_nPID <= 1);

	//The symmetric security parameter (80, 112, 128)
	uint32_t m_nSecParam = 128;

	crypto *crypt = new crypto(m_nSecParam, (uint8_t*)  m_cConstSeed[m_nPID]);
	CLock *glock = new CLock(); // pass this to sender and receiver constructors

	uint32_t m_nBaseOTs = 190;
	uint32_t m_nChecks = 380;

	if(m_nPID == SERVER_ID) //Play as OT sender
	{
		InitSender(addr, port, glock);

		OTExtSnd* sender = NULL;
		for(uint32_t i = 0; i < m_nTests; i++) {
			sender = InitOTExtSnd(tests[i].prot, m_nBaseOTs, m_nChecks, tests[i].usemecr, tests[i].ftype, crypt);

			std::cout << "Test " << i << ": " << getProt(tests[i].prot) << " Sender " << tests[i].numots << " " <<
					getSndFlavor(tests[i].sflavor) << " / " << getRecFlavor(tests[i].rflavor) << " on " <<
					tests[i].bitlen << " bits with " <<	tests[i].nthreads << " threads, " <<
					getFieldType(tests[i].ftype) << " and" << (tests[i].usemecr ? "": " no" ) << " MECR"<< std::endl;

			run_test_sender(tests[i].numots, tests[i].bitlen, tests[i].sflavor, tests[i].rflavor, tests[i].nthreads, crypt, sender);

			delete sender;
		}
		free(tests);
	}
	else //Play as OT receiver
	{
		InitReceiver(addr, port, glock);

		OTExtRec* receiver = NULL;
		for(uint32_t i = 0; i < m_nTests; i++) {
			receiver = InitOTExtRec(tests[i].prot, m_nBaseOTs, m_nChecks, tests[i].usemecr, tests[i].ftype, crypt);

			std::cout << "Test " << i << ": " << getProt(tests[i].prot) << " Receiver " << tests[i].numots << " " <<
					getSndFlavor(tests[i].sflavor) << " / " << getRecFlavor(tests[i].rflavor) << " on " <<
					tests[i].bitlen << " bits with " <<	tests[i].nthreads << " threads, " <<
					getFieldType(tests[i].ftype) << " and" << (tests[i].usemecr ? "": " no" ) << " MECR"<< std::endl;

			run_test_receiver(tests[i].numots, tests[i].bitlen, tests[i].sflavor, tests[i].rflavor, tests[i].nthreads, crypt, receiver);

			delete receiver;
		}
		free(tests);

	}

	Cleanup();
	delete crypt;
	delete glock;

	return EXIT_SUCCESS;
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
		delete(X[i]);
	}
	free(X);
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

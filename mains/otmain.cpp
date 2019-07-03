#include "otmain.h"
#include <cstdlib>
#include <ENCRYPTO_utils/connection.h>

//pthread_mutex_t CLock::share_mtx = PTHREAD_MUTEX_INITIALIZER;

BOOL Init(crypto* crypt)
{
	return TRUE;
}

BOOL Cleanup()
{
	delete sndthread;

	//rcvthread->Wait();

	delete rcvthread;

	//std::cout << "Cleaning" << std::endl;
	//std::cout << "done" << std::endl;
	return true;
}


void InitOTSender(const std::string& address, const int port, crypto* crypt, CLock *glock)
{
#ifdef OTTiming
	timespec np_begin, np_end;
#endif
	m_nPort = (uint16_t) port;
	m_nAddr = &address;

	//Initialize values
	Init(crypt);

	//Server listen
	m_Socket = Listen(address, port);
	if (!m_Socket) {
		std::cerr << "Listen failed on " << address << ":" << port << "\n";
		std::exit(1);
	}

	sndthread = new SndThread(m_Socket.get(), glock);
	rcvthread = new RcvThread(m_Socket.get(), glock);

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

void InitOTReceiver(const std::string& address, const int port, crypto* crypt, CLock *glock)
{
	m_nPort = (uint16_t) port;
	m_nAddr = &address;

	//Initialize values
	Init(crypt);

	//Client connect
	m_Socket = Connect(address, port);
	if (!m_Socket) {
		std::cerr << "Connect failed on " << address << ":" << port << "\n";
		std::exit(1);
	}

	sndthread = new SndThread(m_Socket.get(), glock);
	rcvthread = new RcvThread(m_Socket.get(), glock);

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

	m_Socket->ResetSndCnt();
	m_Socket->ResetRcvCnt();
	timespec ot_begin, ot_end;

	clock_gettime(CLOCK_MONOTONIC, &ot_begin);
	// Execute OT sender routine
	success = sender->send(numOTs, bitlength, nsndvals, X, stype, rtype, m_nNumOTThreads, m_fMaskFct);
	clock_gettime(CLOCK_MONOTONIC, &ot_end);

#ifndef BATCH
	printf("Time spent:\t%f\n", getMillies(ot_begin, ot_end) + rndgentime);
	std::cout << "Sent:\t\t" << m_Socket->getSndCnt() << " bytes" << std::endl;
	std::cout << "Received:\t" << m_Socket->getRcvCnt() <<" bytes" << std::endl;
#else
	std::cout << getMillies(ot_begin, ot_end) + rndgentime << "\t" << m_Socket->getSndCnt() << "\t" << m_Socket->getRcvCnt() << std::endl;
#endif


	return success;
}

BOOL ObliviouslyReceive(CBitVector* choices, CBitVector* ret, int numOTs, int bitlength, uint32_t nsndvals,
		snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt)
{
	bool success = FALSE;

	m_Socket->ResetSndCnt();
	m_Socket->ResetRcvCnt();


	timespec ot_begin, ot_end;
	clock_gettime(CLOCK_MONOTONIC, &ot_begin);
	// Execute OT receiver routine
	success = receiver->receive(numOTs, bitlength, nsndvals, choices, ret, stype, rtype, m_nNumOTThreads, m_fMaskFct);
	clock_gettime(CLOCK_MONOTONIC, &ot_end);

#ifndef BATCH
	printf("Time spent:\t%f\n", getMillies(ot_begin, ot_end) + rndgentime);

	std::cout << "Sent:\t\t" << m_Socket->getSndCnt() << " bytes" << std::endl;
	std::cout << "Received:\t" << m_Socket->getRcvCnt() <<" bytes" << std::endl;
#else
	std::cout << getMillies(ot_begin, ot_end) + rndgentime << "\t" << m_Socket->getSndCnt() << "\t" << m_Socket->getRcvCnt() << std::endl;
#endif


	return success;
}


int main(int argc, char** argv)
{
	std::string addr = "127.0.0.1";
	uint16_t port = 7766;

	//Determines whether the program is executed in the sender or receiver role
	m_nPID = atoi(argv[1]);
	//the number of OTs that are performed.
	uint64_t numOTs = 100000;
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

	read_test_options(&argc, &argv, &m_nPID, &numOTs, &bitlength, &m_nSecParam, &addr, &port, &m_eProt, &stype, &rtype,
			&m_nNumOTThreads, &m_nBaseOTs, &m_nChecks, &nsndvals, &m_bUseMinEntCorAssumption, &runs);

	/*int32_t read_test_options(int32_t* argcp, char*** argvp, uint32_t* role, uint64_t* numots, uint32_t* bitlen,
			uint32_t* secparam, std::string* address, uint16_t* port, ot_ext_prot* protocol, snd_ot_flavor* sndflav,
			rec_ot_flavor* rcvflav, uint32_t* nthreads, uint32_t* nbaseots, uint32_t* nchecks, bool* usemecr, uint32_t* runs) {*/

	crypto *crypt = new crypto(m_nSecParam, (uint8_t*) m_cConstSeed[m_nPID]);
    CLock *glock = new CLock(); // pass this to sender and receiver constructors

	if(m_nPID == SERVER_ID) //Play as OT sender
	{
		InitOTSender(addr, port, crypt, glock);

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
		std::cout << getProt(m_eProt) << " Sender performing " << numOTs << " " << getSndFlavor(stype) << " / " <<
				getRecFlavor(rtype) << " extensions on " << bitlength << " bit elements with " <<	m_nNumOTThreads << " threads, " <<
				getFieldType(m_eFType) << " and" << (m_bUseMinEntCorAssumption ? "": " no" ) << " min-ent-corr-robustness " <<
				runs << " times" << std::endl;
#endif
		for(uint32_t i = 0; i < runs; i++) {
			ObliviouslySend(X, numOTs, bitlength, nsndvals, stype, rtype, crypt);
		}
		/*for(uint32_t i = 0; i < nsndvals; i++) {
			std::cout << "X" << i << ": ";
			X[i]->PrintHex(0, numOTs);
		}*/
	}
	else //Play as OT receiver
	{
		InitOTReceiver(addr, port, crypt, glock);

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
		std::cout << getProt(m_eProt) << " Receiver performing " << numOTs << " " << getSndFlavor(stype) << " / " <<
				getRecFlavor(rtype) << " extensions on " << bitlength << " bit elements with " <<	m_nNumOTThreads << " threads, " <<
				getFieldType(m_eFType) << " and" << (m_bUseMinEntCorAssumption ? "": " no" ) << " min-ent-corr-robustness " <<
				runs << " times" << std::endl;
#endif
		for(uint32_t i = 0; i < runs; i++) {
			ObliviouslyReceive(&choices, &response, numOTs, bitlength, nsndvals, stype, rtype, crypt);
		}
		/*std::cout << "C: ";
		choices.PrintHex(0, numOTs);
		std::cout << "R: ";
		response.PrintHex(0, numOTs);*/

	}

	Cleanup();
	delete crypt;
    delete glock;

	return EXIT_SUCCESS;
}


int32_t read_test_options(int32_t* argcp, char*** argvp, uint32_t* role, uint64_t* numots, uint32_t* bitlen,
		uint32_t* secparam, std::string* address, uint16_t* port, ot_ext_prot* protocol, snd_ot_flavor* sndflav,
		rec_ot_flavor* rcvflav, uint32_t* nthreads, uint32_t* nbaseots, uint32_t* nchecks, uint32_t* N, bool* usemecr,
		uint32_t* runs) {

	uint32_t int_port = 0, int_prot = 0, int_snd_flav = 0, int_rec_flav = 0;
	bool printhelp = false;

	parsing_ctx options[] = {
			{ (void*) role, T_NUM, "r", "Role: 0/1", true, false },
			{ (void*) numots, T_NUM, "n", "Number of OTs, default 10^6", false, false },
			{ (void*) bitlen, T_NUM, "b", "Bit-length of elements in OTs, default 8", false, false },
			{ (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			{ (void*) &int_prot, T_NUM, "o", "Protocol, 0: IKNP, 1: ALSZ, 2: NNOB, 3: KK, default: IKNP", false, false },
			{ (void*) &int_snd_flav, T_NUM, "f", "Sender OT Functionality, 0: OT, 1: C_OT, 2: Snd_R_OT, 3: GC_OT, default: OT", false, false },
			{ (void*) &int_rec_flav, T_NUM, "v", "Receiver OT Functionality, 0: OT, 1: Rec_R_OT, default: OT", false, false },
			{ (void*) nthreads, T_NUM, "t", "Number of threads, default 1", false, false },
			{ (void*) nbaseots, T_NUM, "e", "Number of baseots for ALSZ, default 190", false, false },
			{ (void*) nchecks, T_NUM, "c", "Number of checks for ALSZ, default 380", false, false },
			{ (void*) usemecr, T_FLAG, "m", "Use Min-Entropy Correlation-Robustness Assumption, default: false", false, false },
			{ (void*) runs, T_NUM, "u", "Number of repetitions, default: 1", false, false },
			{ (void*) N, T_NUM, "N", "1-oo-N OT extension. Only works in combination with KK13 and needs to be a power of two, default: 2", false, false },
			{ (void*) &printhelp, T_FLAG, "h", "Print help", false, false }
	};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	if(printhelp) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		std::exit(EXIT_FAILURE);
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
		std::cout << "The N option can only be used in combination with the KK13 OT. Resetting to N=2" << std::endl;
		*N = 2;
	}

	//delete options;

	return 1;
}

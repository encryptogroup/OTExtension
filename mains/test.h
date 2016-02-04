#ifndef _MPC_H_
#define _MPC_H_

#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../util/socket.h"
#include "../ot/iknp-ot-ext-snd.h"
#include "../ot/iknp-ot-ext-rec.h"
#include "../ot/alsz-ot-ext-snd.h"
#include "../ot/alsz-ot-ext-rec.h"
#include "../ot/nnob-ot-ext-snd.h"
#include "../ot/nnob-ot-ext-rec.h"
#include "../util/cbitvector.h"
#include "../ot/xormasking.h"
#include "../util/rcvthread.h"
#include "../util/sndthread.h"
#include "../util/channel.h"

#include <vector>
#include <sys/time.h>

#include <limits.h>
#include <iomanip>
#include <string>

using namespace std;

USHORT		m_nPort = 7894;
const char* m_nAddr ;// = "localhost";

static const char* m_cConstSeed[2] = {"437398417012387813714564100", "15657566154164561"};


struct test_options {
	ot_ext_prot	prot;
	uint64_t numots;
	uint64_t bitlen;
	snd_ot_flavor sflavor;
	rec_ot_flavor rflavor;
	uint32_t nthreads;
	field_type ftype;
	bool usemecr;
};

test_options* tests;
uint32_t m_nTests;
uint32_t gen_tests;
uint32_t m_nPID;

void recursive_assign_test_params(uint32_t* max, uint32_t depth, test_options** tops, uint32_t max_depth);
void assign_param(uint32_t ctr, uint32_t depth, test_options* tops);


BOOL Init();
BOOL Cleanup();
BOOL Connect();
BOOL Listen();

void InitSender(const char* address, int port);
void InitReceiver(const char* address, int port);

OTExtSnd* InitOTExtSnd(ot_ext_prot m_eProt, uint32_t nbaseots, uint32_t nchecks, bool enablemecr, field_type ftype, crypto* crypt);
OTExtRec* InitOTExtRec(ot_ext_prot m_eProt, uint32_t nbaseots, uint32_t nchecks, bool enablemecr, field_type ftype, crypto* crypt);

void run_test_sender(uint32_t numots, uint32_t bitlength, snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numthreads, crypto* crypt, OTExtSnd* sender);
void run_test_receiver(uint32_t numots, uint32_t bitlength, snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numthreads, crypto* crypt, OTExtRec* receiver);

// Network Communication
CSocket* m_vSocket;

SndThread* sndthread;
RcvThread* rcvthread;

#endif

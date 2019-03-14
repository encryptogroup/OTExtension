#ifndef _OTTEST_H_
#define _OTTEST_H_

#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/socket.h>
#include "../ot/iknp-ot-ext-snd.h"
#include "../ot/iknp-ot-ext-rec.h"
#include "../ot/alsz-ot-ext-snd.h"
#include "../ot/alsz-ot-ext-rec.h"
#include "../ot/nnob-ot-ext-snd.h"
#include "../ot/nnob-ot-ext-rec.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include "../ot/xormasking.h"
#include <ENCRYPTO_utils/rcvthread.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/timer.h>

#include <vector>
#include <sys/time.h>

#include <limits.h>
#include <iomanip>
#include <string>

uint16_t m_nPort = 7894;
const std::string* m_nAddr;

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

void InitSender(const std::string& address, const int port, CLock *glock);
void InitReceiver(const std::string& address, const int port, CLock *glock);

OTExtSnd* InitOTExtSnd(ot_ext_prot m_eProt, uint32_t nbaseots, uint32_t nchecks, bool enablemecr, field_type ftype, crypto* crypt);
OTExtRec* InitOTExtRec(ot_ext_prot m_eProt, uint32_t nbaseots, uint32_t nchecks, bool enablemecr, field_type ftype, crypto* crypt);

void run_test_sender(uint32_t numots, uint32_t bitlength, snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numthreads, crypto* crypt, OTExtSnd* sender);
void run_test_receiver(uint32_t numots, uint32_t bitlength, snd_ot_flavor stype, rec_ot_flavor rtype, uint32_t numthreads, crypto* crypt, OTExtRec* receiver);

// Network Communication
std::unique_ptr<CSocket> m_Socket;

SndThread* sndthread;
RcvThread* rcvthread;

#endif


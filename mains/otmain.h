#ifndef _OTMAIN_H_
#define _OTMAIN_H_

#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/socket.h>
#include "../ot/iknp-ot-ext-snd.h"
#include "../ot/iknp-ot-ext-rec.h"
#include "../ot/alsz-ot-ext-snd.h"
#include "../ot/alsz-ot-ext-rec.h"
#include "../ot/nnob-ot-ext-snd.h"
#include "../ot/nnob-ot-ext-rec.h"
#include "../ot/kk-ot-ext-snd.h"
#include "../ot/kk-ot-ext-rec.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include "../ot/xormasking.h"
#include <ENCRYPTO_utils/rcvthread.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/parse_options.h>

#include <vector>
#include <sys/time.h>

#include <limits.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

//TODO only for debugging purpose!!
static const char* m_cConstSeed[2] = {"437398417012387813714564100", "15657566154164561"};

uint16_t m_nPort = 7766;
const std::string* m_nAddr;

BOOL Init(crypto* crypt);
BOOL Cleanup();

void InitOTSender(const std::string& address, const int port, crypto* crypt);
void InitOTReceiver(const std::string &address, const int port, crypto* crypt);

BOOL ObliviouslyReceive(CBitVector* choices, CBitVector* ret, int numOTs, int bitlength, uint32_t nsndvals, snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt);
BOOL ObliviouslySend(CBitVector** X, int numOTs, int bitlength, uint32_t nsndvals, snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt);

// Network Communication
std::unique_ptr<CSocket> m_Socket;
uint32_t m_nPID; // thread id
field_type m_eFType;
uint32_t m_nBitLength;
MaskingFunction* m_fMaskFct;

// Naor-Pinkas OT
//BaseOT* bot;
OTExtSnd *sender;
OTExtRec *receiver;

SndThread* sndthread;
RcvThread* rcvthread;

uint32_t m_nNumOTThreads;
uint32_t m_nBaseOTs;
uint32_t m_nChecks;

bool m_bUseMinEntCorAssumption;
ot_ext_prot m_eProt;

double rndgentime;

int32_t read_test_options(int32_t* argcp, char*** argvp, uint32_t* role, uint64_t* numots, uint32_t* bitlen,
		uint32_t* secparam, std::string* address, uint16_t* port, ot_ext_prot* protocol, snd_ot_flavor* sndflav,
		rec_ot_flavor* rcvflav, uint32_t* nthreads, uint32_t* nbaseots, uint32_t* nchecks, uint32_t* N, bool* usemecr, uint32_t* runs);

#endif


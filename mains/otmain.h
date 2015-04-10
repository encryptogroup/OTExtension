#ifndef _MPC_H_
#define _MPC_H_

#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../util/socket.h"
#include "../ot/iknp-ot-ext-snd.h"
#include "../ot/iknp-ot-ext-rec.h"
#include "../ot/alsz-ot-ext-snd.h"
#include "../ot/alsz-ot-ext-rec.h"
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

//TODO only for debugging purpose!!
static const char* m_cConstSeed[2] = {"437398417012387813714564100", "15657566154164561"};

USHORT		m_nPort = 7766;
const char* m_nAddr ;// = "localhost";

BOOL Init(crypto* crypt);
BOOL Cleanup();
BOOL Connect();
BOOL Listen();

void InitOTSender(const char* address, int port, crypto* crypt);
void InitOTReceiver(const char* address, int port, crypto* crypt);

//BOOL PrecomputeNaorPinkasSender(crypto* crypt);
//BOOL PrecomputeNaorPinkasReceiver(crypto* crypt);
BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt);
BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, snd_ot_flavor stype, rec_ot_flavor rtype, crypto* crypt);

// Network Communication
CSocket* m_vSocket;
int m_nPID; // thread id
field_type m_eFType;
int m_nBitLength;
int m_nMod;
MaskingFunction* m_fMaskFct;

// Naor-Pinkas OT
//BaseOT* bot;
OTExtSnd *sender;
OTExtRec *receiver;

SndThread* sndthread;
RcvThread* rcvthread;

int m_nNumOTThreads;
uint32_t m_nBaseOTs;
uint32_t m_nChecks;

bool m_bUseMinEntCorAssumption;
ot_ext_prot m_eProt;

double rndgentime;

#endif //_MPC_H_

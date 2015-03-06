#ifndef _MPC_H_
#define _MPC_H_

#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../util/socket.h"
#include "../ot/naor-pinkas.h"
#include "../ot/naor-pinkas_noro.h"
//#include "../ot/asharov-lindell.h"
//#include "../ot/ot-ext.h"
//#include "../ot/ot-ext-rec.h"
#include "../ot/iknp-ot-ext-snd.h"
#include "../ot/iknp-ot-ext-rec.h"
#include "../util/cbitvector.h"
#include "../ot/xormasking.h"


#include <vector>
#include <sys/time.h>

#include <limits.h>
#include <iomanip>
#include <string>

using namespace std;

static const char* m_nSeed = "437398417012387813714564100";

USHORT		m_nPort = 7766;
const char* m_nAddr ;// = "localhost";

BOOL Init(crypto* crypt);
BOOL Cleanup();
BOOL Connect();
BOOL Listen();

void InitOTSender(const char* address, int port, crypto* crypt);
void InitOTReceiver(const char* address, int port, crypto* crypt);

BOOL PrecomputeNaorPinkasSender(crypto* crypt);
BOOL PrecomputeNaorPinkasReceiver(crypto* crypt);
BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, eot_flavor version, crypto* crypt);
BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, eot_flavor version, crypto* crypt);

// Network Communication
CSocket* m_vSockets;
int m_nPID; // thread id
bool m_bUseECC;
int m_nBitLength;
int m_nMod;
MaskingFunction* m_fMaskFct;

// Naor-Pinkas OT
BaseOT* bot;
IKNPOTExtSnd *sender;
IKNPOTExtRec *receiver;
CBitVector U; 
BYTE *vKeySeeds;
BYTE *vKeySeedMtx;

int m_nNumOTThreads;

double rndgentime;

#endif //_MPC_H_

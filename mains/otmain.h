#ifndef _MPC_H_
#define _MPC_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../ot/naor-pinkas.h"
#include "../ot/asharov-lindell.h"
#include "../ot/ot-extension.h"
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

BOOL Init();
BOOL Cleanup();
BOOL Connect();
BOOL Listen();

void InitOTSender(const char* address, int port);
void InitOTReceiver(const char* address, int port);

BOOL PrecomputeNaorPinkasSender();
BOOL PrecomputeNaorPinkasReceiver();
BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version);
BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version, CBitVector& delta);

// Network Communication
vector<CSocket> m_vSockets;
int m_nPID; // thread id
int m_nSecParam; 
bool m_bUseECC;
int m_nBitLength;
int m_nMod;
MaskingFunction* m_fMaskFct;

// Naor-Pinkas OT
BaseOT* bot;
OTExtensionSender *sender;
OTExtensionReceiver *receiver;
CBitVector U; 
BYTE *vKeySeeds;
BYTE *vKeySeedMtx;

int m_nNumOTThreads;

// SHA PRG
BYTE				m_aSeed[SHA1_BYTES];
int			m_nCounter;
double			rndgentime;


#endif //_MPC_H_

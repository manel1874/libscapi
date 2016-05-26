#pragma once
#ifndef _OTMAIN_MALICIOUS_H_
#define _OTMAIN_MALICIOUS_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../ot/ot-extension-malicious.h"
#include "../util/CBitVector.h"
#include "../ot/xormasking.h"
#include "../ot/pvwddh.h"


#include <vector>
#include <time.h>

#include <limits.h>
#include <iomanip>
#include <string>

using namespace std;

namespace maliciousot {

	static const char* m_nSeed = "437398417012387813714564100";

	USHORT		m_nPort = 7766;
	const char* m_nAddr;// = "localhost";

	BOOL Init();
	BOOL Cleanup();
	BOOL Connect();
	BOOL Listen();

	void InitOTSender(const char* address, int port, int nbaseots, int numOTs);
	void InitOTReceiver(const char* address, int port, int nbaseots, int numOTs);

	BOOL PrecomputeBaseOTsSender(int nbaseots);
	BOOL PrecomputeBaseOTsReceiver(int nbaseots);
	BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version);
	BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version);

	// Network Communication
	vector<CSocket> m_vSockets;
	int m_nPID; // thread id
	SECLVL m_sSecLvl;
	bool m_bUseECC;
	int m_nBitLength;
	int m_nMod;
	MaskingFunction* m_fMaskFct;

	// Naor-Pinkas OT
	BaseOT* bot;
	Mal_OTExtensionSender *sender;
	Mal_OTExtensionReceiver *receiver;
	CBitVector U;
	BYTE *vKeySeeds;
	BYTE *vKeySeedMtx;

	int m_nNumOTThreads;

	// SHA PRG
	BYTE				m_aSeed[SHA1_BYTES];
	BYTE				m_aOTSeed[AES_BYTES];
	int			m_nCounter;
	double			rndgentime;
	int 		m_nChecks;
}

#endif //_OTMAIN_MALICIOUS_H_

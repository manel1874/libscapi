#pragma once
/*
 * Compute the Base OTs using the Peikert-Vakuntanathan-Waters OT based on DDH in decryption mode (PVW08)
 */
#ifndef __PVWDDH_H_
#define __PVWDDH_H_

#include "baseOT.h"
namespace maliciousot {

	class PVWDDH : public BaseOT
	{

	public:

		PVWDDH() {};
		~PVWDDH() {};

		PVWDDH(SECLVL sec, BYTE* seed) { Init(sec, seed); };

		BOOL Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
		BOOL Sender(int nSndVals, int nOTs, CSocket& sock, BYTE* ret);


	};
}
#endif

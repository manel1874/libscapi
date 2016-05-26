#include "otmain-malicious.h"

//#define OTTiming
namespace maliciousot {

	BOOL Init()
	{
		BYTE		seedtmp[SHA1_BYTES];

		// Random numbers
		HASH_CTX sha;
		MPC_HASH_INIT(&sha);
		MPC_HASH_UPDATE(&sha, (BYTE*)&m_nPID, sizeof(m_nPID));
		MPC_HASH_UPDATE(&sha, (BYTE*)m_nSeed, sizeof(m_nSeed));
		MPC_HASH_FINAL(&sha, m_aSeed);

		MPC_HASH_INIT(&sha);
		MPC_HASH_UPDATE(&sha, (BYTE*)&m_nPID, sizeof(m_nPID));
		MPC_HASH_UPDATE(&sha, (BYTE*)m_aSeed, SHA1_BYTES);
		MPC_HASH_FINAL(&sha, seedtmp);
		memcpy(m_aOTSeed, seedtmp, AES_BYTES);

		m_nCounter = 0;

		//Number of threads that will be used in OT extension
		m_vSockets.resize(m_nNumOTThreads + 1);
		bot = new PVWDDH(m_sSecLvl, m_aSeed);


		return TRUE;
	}

	BOOL Cleanup()
	{
		for (int i = 0; i < m_nNumOTThreads; i++)
		{
			m_vSockets[i].Close();
		}
		return true;
	}


	BOOL Connect()
	{
		BOOL bFail = FALSE;
		LONG lTO = CONNECT_TIMEO_MILISEC;
		int nconnections = m_nNumOTThreads + 1;

#ifndef BATCH
		cerr << "Connecting to party " << !m_nPID << ": " << m_nAddr << ", " << m_nPort << endl;
#endif
		for (int k = nconnections - 1; k >= 0; k--)
		{
			for (int i = 0; i < RETRY_CONNECT; i++)
			{
				if (!m_vSockets[k].Socket())
				{
					printf("Socket failure: ");
					goto connect_failure;
				}

				if (m_vSockets[k].Connect(m_nAddr, m_nPort, lTO))
				{
					// send pid when connected
					m_vSockets[k].Send(&k, sizeof(int));
#ifndef BATCH
					cerr << " (" << !m_nPID << ") (" << k << ") connected" << endl;
#endif
					if (k == 0)
					{
						//cerr << "connected" << endl;
						return TRUE;
					}
					else
					{
						break;
					}
					SleepMiliSec(10);
					m_vSockets[k].Close();
				}
				SleepMiliSec(20);
				if (i + 1 == RETRY_CONNECT)
					goto server_not_available;
			}
		}
	server_not_available:
		printf("Server not available: ");
	connect_failure:
		cerr << " (" << !m_nPID << ") connection failed" << endl;
		return FALSE;
	}



	BOOL Listen()
	{
#ifndef BATCH
		cerr << "Listening: " << m_nAddr << ":" << m_nPort << ", with size: " << m_nNumOTThreads << endl;
#endif
		int nconnections = m_nNumOTThreads + 1;

		if (!m_vSockets[0].Socket())
		{
			goto listen_failure;
		}
		if (!m_vSockets[0].Bind(m_nPort, m_nAddr))
			goto listen_failure;
		if (!m_vSockets[0].Listen())
			goto listen_failure;

		for (int i = 0; i < nconnections; i++) //twice the actual number, due to double sockets for OT
		{
			CSocket sock;
			//cerr << "New round! " << endl;
			if (!m_vSockets[0].Accept(sock))
			{
				cerr << "Error in accept" << endl;
				goto listen_failure;
			}

			UINT threadID;
			sock.Receive(&threadID, sizeof(int));

			if (threadID >= nconnections)
			{
				sock.Close();
				i--;
				continue;
			}

#ifndef BATCH
			cerr << " (" << m_nPID << ") (" << threadID << ") connection accepted" << endl;
#endif
			// locate the socket appropriately
			m_vSockets[threadID].AttachFrom(sock);
			sock.Detach();
		}

#ifndef BATCH
		cerr << "Listening finished" << endl;
#endif
		return TRUE;

	listen_failure:
		cerr << "Listen failed" << endl;
		return FALSE;
	}




	void InitOTSender(const char* address, int port, int nbaseots, int numOTs)
	{
		int nSndVals = 2;
		int wdsize = 1 << (CEIL_LOG2(nbaseots));
		int nblocks = CEIL_DIVIDE(numOTs, NUMOTBLOCKS * wdsize);
		int s2ots = nblocks * nbaseots;
#ifdef OTTiming
		timeval np_begin, np_end, s2_begin, s2_end;
#endif
		m_nPort = (USHORT)port;
		m_nAddr = address;
		//key seed matrix used for the 1-step base OTs
		vKeySeedMtx = (BYTE*)malloc(AES_KEY_BYTES*nbaseots* nSndVals);
		//key seeds for the 2-nd step base OTs
		vKeySeeds = (BYTE*)malloc(AES_KEY_BYTES * s2ots);//m_sSecLvl.symbits);
		//Initialize values
		Init();

		//Server listen
		Listen();


#ifdef OTTiming
		gettimeofday(&np_begin, NULL);
#endif

		PrecomputeBaseOTsSender(nbaseots);

#ifdef OTTiming
		gettimeofday(&np_end, NULL);
#ifdef BATCH
		cerr << getMillies(np_begin, np_end) << "\t";
#else
		printf("Time for performing the NP base-OTs: %f ms\n", getMillies(np_begin, np_end));
#endif
		gettimeofday(&s2_begin, NULL);
#endif	

		CBitVector seedcbitvec;
		CBitVector U(s2ots, m_aSeed, m_nCounter);
		CBitVector URev(s2ots);

		seedcbitvec.AttachBuf(vKeySeeds, AES_KEY_BYTES * s2ots);

		XORMasking* mskfct = new XORMasking(AES_KEY_BITS);

		assert(nblocks <= NUMOTBLOCKS);

		//cerr << "Initializing OT extension receiver " << endl;
		//perform the 2nd OT extension step to obtain the base-OTs for the next step
		receiver = new Mal_OTExtensionReceiver(nSndVals, m_sSecLvl.symbits, m_vSockets.data(), vKeySeedMtx, m_aSeed, nbaseots, s2ots);

		receiver->receive(s2ots, AES_KEY_BITS, U, seedcbitvec, R_OT, 1, mskfct);

		for (int i = 0; i < s2ots; i++) {
			//cerr << i << ": " << (hex) << ((uint64_t*) (vKeySeeds +  i * AES_KEY_BYTES))[0] << ((uint64_t*)(vKeySeeds + i * AES_KEY_BYTES))[1] << (dec) << endl;
			URev.SetBit(i, U.GetBitNoMask(i));
		}
		//URev.PrintBinary();
		sender = new Mal_OTExtensionSender(nSndVals, m_sSecLvl.symbits, m_vSockets.data(), URev, vKeySeeds, nbaseots, m_nChecks, s2ots, m_aOTSeed);
#ifdef OTTiming
		gettimeofday(&s2_end, NULL);
#ifdef BATCH
		cerr << getMillies(s2_begin, s2_end) << "\t";
#else
		printf("Time for performing the 2nd-step base-OTs: %f ms\n", getMillies(s2_begin, s2_end));
#endif
#endif
	}

	void InitOTReceiver(const char* address, int port, int nbaseots, int numOTs)
	{
		int nSndVals = 2;
		int wdsize = 1 << (CEIL_LOG2(nbaseots));
		int nblocks = CEIL_DIVIDE(numOTs, NUMOTBLOCKS * wdsize);
		int s2ots = nblocks * nbaseots;
		//cerr << "nblocks = " << nblocks <<", baseots = " << nbaseots << ", s2ots: " << s2ots << endl;

#ifdef OTTiming
		timeval np_begin, np_end, s2_begin, s2_end;
#endif
		m_nPort = (USHORT)port;
		m_nAddr = address;
		vKeySeeds = (BYTE*)malloc(AES_KEY_BYTES*nbaseots);//m_sSecLvl.symbits);
		vKeySeedMtx = (BYTE*)malloc(AES_KEY_BYTES * 2 * s2ots);

		//Initialize values
		Init();

		//Client connect
		Connect();

#ifdef OTTiming
		gettimeofday(&np_begin, NULL);
#endif

		//First step: pre-compute the PVW base OTs
		PrecomputeBaseOTsReceiver(nbaseots);

#ifdef OTTiming
		gettimeofday(&np_end, NULL);
#ifdef BATCH
		cerr << getMillies(np_begin, np_end) << "\t";
#else
		printf("Time for performing the NP base-OTs: %f ms\n", getMillies(np_begin, np_end));
#endif
		gettimeofday(&s2_begin, NULL);
#endif	

		assert(nblocks <= NUMOTBLOCKS);

		//perform the 2nd OT extension step to obtain the base-OTs for the next step
		sender = new Mal_OTExtensionSender(nSndVals, m_sSecLvl.symbits, m_vSockets.data(), U, vKeySeeds, nbaseots, m_nChecks, s2ots, m_aOTSeed);
		CBitVector seedA(s2ots * AES_KEY_BITS);
		CBitVector seedB(s2ots * AES_KEY_BITS);

		XORMasking* mskfct = new XORMasking(AES_KEY_BITS);
		sender->send(s2ots, AES_KEY_BITS, seedA, seedB, R_OT, 1, mskfct);

		for (int i = 0; i < s2ots; i++) {
			memcpy(vKeySeedMtx + 2 * i * AES_KEY_BYTES, seedA.GetArr() + i * AES_KEY_BYTES, AES_KEY_BYTES);
			memcpy(vKeySeedMtx + (2 * i + 1) * AES_KEY_BYTES, seedB.GetArr() + i * AES_KEY_BYTES, AES_KEY_BYTES);
		}
		receiver = new Mal_OTExtensionReceiver(nSndVals, m_sSecLvl.symbits, m_vSockets.data(), vKeySeedMtx, m_aSeed, nbaseots, s2ots);
#ifdef OTTiming
		gettimeofday(&s2_end, NULL);
#ifdef BATCH
		cerr << getMillies(s2_begin, s2_end) << "\t";
#else
		printf("Time for performing the 2nd-step base-OTs: %f ms\n", getMillies(s2_begin, s2_end));
#endif
#endif
	}



	BOOL PrecomputeBaseOTsReceiver(int numbaseOTs)
	{

		int nSndVals = 2;
		BYTE* pBuf = new BYTE[numbaseOTs * SHA1_BYTES];
		int log_nVals = (int)ceil(log((double)nSndVals) / log((double)2)), cnt = 0;

		U.Create(numbaseOTs*log_nVals, m_aSeed, cnt);

		bot->Receiver(nSndVals, numbaseOTs, U, m_vSockets[0], pBuf);

		//Key expansion
		BYTE* pBufIdx = pBuf;
		for (int i = 0; i < numbaseOTs; i++) //80 HF calls for the Naor Pinkas protocol
		{
			memcpy(vKeySeeds + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
			pBufIdx += SHA1_BYTES;
		}
		delete[] pBuf;

		return true;
	}

	BOOL PrecomputeBaseOTsSender(int numbaseOTs)
	{
		int nSndVals = 2;
		// Execute NP receiver routine and obtain the key 
		BYTE* pBuf = new BYTE[SHA1_BYTES * numbaseOTs * nSndVals];

		//=================================================	
		bot->Sender(nSndVals, numbaseOTs, m_vSockets[0], pBuf);

		BYTE* pBufIdx = pBuf;
		for (int i = 0; i < numbaseOTs * nSndVals; i++)
		{
			memcpy(vKeySeedMtx + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
			pBufIdx += SHA1_BYTES;
		}

		delete[] pBuf;

		return true;
	}


	BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version)
	{
		bool success = FALSE;
		int nSndVals = 2; //Perform 1-out-of-2 OT
#ifdef OTTiming
		timeval ot_begin, ot_end;
#endif


#ifdef OTTiming
		gettimeofday(&ot_begin, NULL);
#endif
		// Execute OT sender routine 	
		success = sender->send(numOTs, bitlength, X1, X2, version, m_nNumOTThreads, m_fMaskFct);

#ifdef OTTiming
		gettimeofday(&ot_end, NULL);
#ifdef BATCH
		cerr << getMillies(ot_begin, ot_end) + rndgentime << "\t";
#else
		printf("Sender: time for OT extension %f ms\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
#endif
		return success;
	}

	BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version)
	{
		bool success = FALSE;

#ifdef OTTiming
		timeval ot_begin, ot_end;
		gettimeofday(&ot_begin, NULL);
#endif
		// Execute OT receiver routine 	
		success = receiver->receive(numOTs, bitlength, choices, ret, version, m_nNumOTThreads, m_fMaskFct);

#ifdef OTTiming
		gettimeofday(&ot_end, NULL);
#ifdef BATCH
		cerr << getMillies(ot_begin, ot_end) + rndgentime << "\t";
#else
		printf("Receiver: time for OT extension %f ms\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
#endif


		return success;
	}

	int main(int argc, char** argv)
	{
		const char* addr = "127.0.0.1";
		int port = 7766;

		if (argc < 3)
		{
			cerr << "Call as: ./mal_ot.exe role numOTs bitlen baseOTs checks ip-server" << endl;
			cerr << "role: [0/1], 0 = server, 1 = client" << endl;
			cerr << "numOTs: [int] Number of OTs" << endl;
			cerr << "bitlen: [int] Bit-Length of the transferred strings (default:128)" << endl;
			cerr << "baseOTs: [int] number of baseOTs (default 190)" << endl;
			cerr << "checks: [int] number of checks (default 380)" << endl;
			cerr << "ip-server: [char*] (default 127.0.0.1)" << endl;
			return 0;
		}

		//Determines whether the program is executed in the sender or receiver role
		m_nPID = atoi(argv[1]);
#ifndef BATCH
		cerr << "Playing as role: " << m_nPID << endl;
#endif
		//the number of OTs that are performed. Has to be initialized to a certain minimum size due to
		int numOTs = 10000000;
		//The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
		m_sSecLvl = LT;
		//bitlength of the values that are transferred - NOTE that when bitlength is not 1 or a multiple of 8, the endianness has to be observed
		int bitlength = 128;
		//The masking function with which the values that are sent in the last communication step are processed
		//Choose OT extension version: G_OT, C_OT or R_OT
		BYTE version = G_OT; // C_OT
		//Use elliptic curve cryptography in the base-OTs
		m_bUseECC = true;
		//Number of base OTs that need to be performed
		int nbaseots = 190;
		//Number of threads in OT extension
		m_nNumOTThreads = 1;
		//Number of checks between the base-OTs	
		m_nChecks = 380;

		numOTs = atoi(argv[2]);

		if (argc > 3) {
			bitlength = atoi(argv[3]);
			if (argc > 4) {
				nbaseots = atoi(argv[4]);
				if (argc > 5) {
					m_nChecks = atoi(argv[5]);
					if (argc > 6) {
						addr = argv[6];
					}
				}
			}
		}


#ifdef OTTiming
		timeval total_begin, total_end;
		gettimeofday(&total_begin, NULL);
#endif

		if (m_nPID == 0) //Play as OT sender
		{
			InitOTSender(addr, port, nbaseots, numOTs);

			CBitVector delta, X1, X2;

			//delta holds the correlation between X1 and X2 in the C-OT version
			delta.Create(numOTs, bitlength, m_aSeed, m_nCounter);
			m_fMaskFct = new XORMasking(bitlength, delta);

			//Create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values and resets them to 0
			X1.Create(numOTs, bitlength);
			X2.Create(numOTs, bitlength);


#ifndef BATCH
			cerr << "Sender performing " << numOTs << " OT extensions on " << bitlength << " bit elements" << endl;
#endif
			ObliviouslySend(X1, X2, numOTs, bitlength, version);
		}
		else //Play as OT receiver
		{
			InitOTReceiver(addr, port, nbaseots, numOTs);

			CBitVector choices, response;
			m_fMaskFct = new XORMasking(bitlength);
			choices.Create(numOTs, m_aSeed, m_nCounter);

			//Pre-generate the respose vector for the results
			response.Create(numOTs, bitlength);


#ifndef BATCH
			cerr << "Receiver performing " << numOTs << " OT extensions on " << bitlength << " bit elements" << endl;
#endif
			ObliviouslyReceive(choices, response, numOTs, bitlength, version);
		}

#ifdef OTTiming
		gettimeofday(&total_end, NULL);
#ifdef BATCH
		cerr << getMillies(total_begin, total_end) << endl;
#else
		printf("Time for performing the overall evaluation: %f ms\n", getMillies(total_begin, total_end));
#endif
#endif
		Cleanup();

		return 1;
	}

}
#include "ot-extension-malicious.h"


namespace maliciousot {

BOOL Mal_OTExtensionReceiver::receive(int numOTs, int bitlength, CBitVector& choices, CBitVector& ret, BYTE type, int numThreads, MaskingFunction* unmaskfct)
{
		m_nOTs = numOTs;
		m_nBitLength = bitlength;
		m_nChoices = choices;
		m_nRet = ret;
		m_bProtocol = type;
		m_fMaskFct = unmaskfct;
		return receive(numThreads);
};

//Initialize and start numThreads OTSenderThread
BOOL Mal_OTExtensionReceiver::receive(int numThreads)
{
	if(m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs));
	int internal_numOTs = CEIL_DIVIDE(PadToMultiple(m_nOTs, wd_size_bits), numThreads);

	//BYTE go;
	//Wait for the signal of the corresponding sender thread
	//sock.Receive(&go, 1);

	//Create temporary result buf to which the threads write their temporary masks
	m_vTempOTMasks.Create(internal_numOTs * numThreads * m_nBitLength);

	m_tSeedHead = NULL;
	m_tSeedTail = NULL;

	vector<OTReceiverThread*> rThreads(numThreads); 
	for(int i = 0; i < numThreads; i++)
	{
		rThreads[i] = new OTReceiverThread(i, internal_numOTs, this);
		rThreads[i]->Start();
	}
	
	ReceiveAndProcess(numThreads);

	for(int i = 0; i < numThreads; i++) 	{
		rThreads[i]->Wait();
	}
	m_nCounter += m_nOTs;

	for(int i = 0; i < numThreads; i++)
		delete rThreads[i];

	if(m_bProtocol == R_OT || m_bProtocol == OCRS_OT) {
		m_nRet.Copy(m_vTempOTMasks.GetArr(), 0, CEIL_DIVIDE(m_nOTs * m_nBitLength, 8));
		m_vTempOTMasks.delCBitVector();
	}

#ifdef VERIFY_OT
	//Wait for the signal of the corresponding sender thread
	BYTE finished = 0x01;
	m_vSockets[0].Send(&finished, 1);
	verifyOT(m_nOTs);
#endif


	return true;
}



BOOL Mal_OTExtensionReceiver::OTReceiverRoutine(int id, int myNumOTs)
{
	//cerr << "Thread " << id << " started" << endl;
	int myStartPos = id * myNumOTs;
	int i = myStartPos, nProgress = myStartPos;
	int RoundWindow = 2;
	int roundctr = 0;
	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs));
	//cerr << "window size = " << wd_size_bits << endl;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	int lim = myStartPos+myNumOTs;

	int processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(myNumOTs, wd_size_bits));
	int OTsPerIteration = processedOTBlocks * wd_size_bits;
	int OTwindow = NUMOTBLOCKS*wd_size_bits*RoundWindow;
	CSocket sock = m_vSockets[id];

	//counter variables
	int numblocks = CEIL_DIVIDE(myNumOTs, OTsPerIteration);
	int nSize;

	// The receive buffer
	CBitVector vRcv;
	if(m_bProtocol == G_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	else if(m_bProtocol == C_OT || m_bProtocol == S_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength);

	// A temporary part of the T matrix
	CBitVector T(wd_size_bits * OTsPerIteration);

	// The send buffer
	CBitVector vSnd(m_nBaseOTs * OTsPerIteration);
	//cerr << "vSnd size = " << m_nBaseOTs * OTsPerIteration << "(" << m_nBaseOTs << ", " << OTsPerIteration << ")" << endl;

	// A temporary buffer that stores the resulting seeds from the hash buffer
	CBitVector seedbuf(OTwindow*AES_KEY_BITS);// = new CBitVector[RoundWindow];


	BYTE ctr_buf[AES_BYTES] = {0};
	int* counter = (int*) ctr_buf;
	(*counter) = myStartPos + m_nCounter;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalChkTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( i < lim )
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(lim-i, wd_size_bits));
 		OTsPerIteration = processedOTBlocks * wd_size_bits;
		nSize = CEIL_DIVIDE(m_nBaseOTs* OTsPerIteration, 8);

#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, vSnd, processedOTBlocks, i, ctr_buf);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalMtxTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		T.EklundhBitTranspose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		//cerr << "offset: " << (AES_KEY_BYTES * (i-nProgress))<< ", i = " << i << ", nprogress = " << nProgress << ", otwindow = " << OTwindow << endl;
		HashValues(T, seedbuf, i, min(lim-i, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalHshTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif

 		sock.Send( vSnd.GetArr(), nSize );
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalSndTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		(*counter)+=min(lim-i, OTsPerIteration);
		i+=min(lim-i, OTsPerIteration);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
#endif


#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
 		//TODO: Consistency Check Hashes
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalChkTime += getMillies(tempStart, tempEnd);
#endif
 		vSnd.Reset();
 		T.Reset();
	}

	T.delCBitVector();
	vSnd.delCBitVector();
	vRcv.delCBitVector();
	seedbuf.delCBitVector();

#ifdef OTTiming
	cerr << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cerr << "Time needed for: " << endl;
	cerr << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cerr << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cerr << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cerr << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cerr << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
	cerr << "\t Checking Consistency:\t" << totalChkTime << " ms" << endl;
#endif
#ifndef BATCH
	//cerr << "Receiver finished successfully" << endl;
#endif
	//sleep(1);
	return TRUE;
}



void Mal_OTExtensionReceiver::BuildMatrices(CBitVector& T, CBitVector& SndBuf, int numblocks, int ctr, BYTE* ctr_buf)
{
	int* counter = (int*) ctr_buf;
	int tempctr = (*counter);
	int wd_size_bytes = 1 << (CEIL_LOG2(m_nBaseOTs) - 3);
	int rowbytelen = wd_size_bytes * numblocks;

	BYTE* Tptr = T.GetArr();
	BYTE* sndbufptr = SndBuf.GetArr();
	BYTE* choiceptr;

	AES_KEY_CTX* seedptr = m_vKeySeedMtx;
	//How many blocks have been processed until now
	int blockoffset = CEIL_DIVIDE(ctr, NUMOTBLOCKS * wd_size_bytes * 8);
	//cerr << "Using block: " << blockoffset << " total = " << (m_nBaseOTs * m_nSndVals * blockoffset) << ", and numblocks = " << numblocks << ", baseOTs = " << m_nBaseOTs << ", m_nSndVals = " << m_nSndVals << endl;
	seedptr += (m_nBaseOTs * m_nSndVals * blockoffset);

	for(int k = 0; k < m_nBaseOTs; k++) 	{
		for(int b = 0; b < rowbytelen/ AES_BYTES; b++, (*counter)++) {
			MPC_AES_ENCRYPT(seedptr + 2*k, Tptr, ctr_buf);
#ifdef DEBUG_MALICIOUS
			cerr << "correct: Tka = " << k << ": " << (hex) << ((uint64_t*) Tptr)[0] << ((uint64_t*) Tptr)[1] << (hex) << endl;
#endif
			Tptr+=AES_BYTES;

			MPC_AES_ENCRYPT(seedptr + (2*k) + 1, sndbufptr, ctr_buf);
#ifdef DEBUG_MALICIOUS
			cerr << "correct: Tkb = " << k << ": " << (hex) << ((uint64_t*) sndbufptr)[0] << ((uint64_t*) sndbufptr)[1] << (hex) << endl;
#endif
			sndbufptr+=AES_BYTES;
		}
		(*counter) = tempctr;
	}


	EnqueueSeed(T.GetArr(), SndBuf.GetArr(), ctr, numblocks);

	choiceptr = m_nChoices.GetArr() + CEIL_DIVIDE(ctr, 8);
	for(int k = 0; k < m_nBaseOTs; k++) 	{
		SndBuf.XORBytesReverse(choiceptr, k*rowbytelen, rowbytelen);
	}

	SndBuf.XORBytes(T.GetArr(), 0, rowbytelen*m_nBaseOTs);
}



void Mal_OTExtensionReceiver::HashValues(CBitVector& T, CBitVector& seedbuf, int ctr, int processedOTs)
{
	BYTE* Tptr = T.GetArr();
	BYTE* bufptr = seedbuf.GetArr();//m_vSeedbuf.GetArr() + ctr * AES_KEY_BYTES;//seedbuf.GetArr();

	HASH_CTX sha;
	BYTE hash_buf[SHA1_BYTES];

	int wd_size_bytes = (1 << ((CEIL_LOG2(m_nBaseOTs))-3));
	int hashinbytelen = CEIL_DIVIDE(m_nBaseOTs,8);

	for(int i = ctr; i < ctr+processedOTs; i++, Tptr+=wd_size_bytes, bufptr+=AES_KEY_BYTES)
	{
		if((m_bProtocol == S_OT || m_bProtocol == OCRS_OT) && m_nChoices.GetBitNoMask(i) == 0)
		{
			continue;
		}

#ifdef OT_HASH_DEBUG
			cerr << "Hash-In for i = " << i << ": " << (hex);
			for(int p = 0; p < hashinbytelen; p++)
				cerr << (unsigned int) Tptr[p];
			cerr << (dec) << ", choice-bit = " << (unsigned int) m_nChoices.GetBitNoMask(i) << endl;
#endif

#ifdef FIXED_KEY_AES_HASHING
		FixedKeyHashing(m_kCRFKey, bufptr, Tptr, hash_buf, i, CEIL_DIVIDE(m_nBaseOTs,8));
#else
		MPC_HASH_INIT(&sha);
		MPC_HASH_UPDATE(&sha, (BYTE*) &i, sizeof(i));
		MPC_HASH_UPDATE(&sha, Tptr, CEIL_DIVIDE(m_nBaseOTs,8));
		MPC_HASH_FINAL(&sha, hash_buf);

		memcpy(bufptr, hash_buf, AES_KEY_BYTES);
#endif
	}

	m_fMaskFct->expandMask(m_vTempOTMasks, seedbuf.GetArr(), ctr, processedOTs, m_nBitLength);
}


//void OTExtensionReceiver::ReceiveAndProcess(CBitVector& vRcv, CBitVector& seedbuf, int id, int ctr, int processedOTs)
void Mal_OTExtensionReceiver::ReceiveAndProcess(int numThreads)
{
	int progress = 0;
	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs));
	int threadOTs = CEIL_DIVIDE(PadToMultiple(m_nOTs, wd_size_bits), numThreads);
	int processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(threadOTs, wd_size_bits));
	int OTsPerIteration = processedOTBlocks * wd_size_bits;
	int processedOTs;
	int otid;
	int rcvbytes;
	CBitVector vRcv;
	int i;
	int csockid = numThreads;
	rcv_check_t chk_vals;
	BYTE success;
#ifdef OTTiming
	double totalUnmaskTime = 0, totalCheckTime = 0;
	timeval tempStart, tempEnd;
#endif

	if(m_bProtocol == G_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	else if(m_bProtocol == C_OT || m_bProtocol == S_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength);


	while(progress < m_nOTs)
	{
		//cerr << "Waiting for block " << endl;
		//cerr << "Processing blockid " << OTid;
		m_vSockets[csockid].Receive((BYTE*) &otid, sizeof(int));
		m_vSockets[csockid].Receive((BYTE*) &processedOTs, sizeof(int));

		chk_vals.otid = otid;
		chk_vals.processedOTs = processedOTs;
		//receive: idfirstot, #processedOTs, threadid, #checks, permbits
		m_vSockets[csockid].Receive((BYTE*) &(chk_vals.threadid), sizeof(int));
		m_vSockets[csockid].Receive((BYTE*) &(chk_vals.nchecks), sizeof(int));
#ifdef DEBUG_MALICIOUS
		cerr << "Checking otid = " << chk_vals.otid << " of len " << processedOTs << " for thread "
				<< chk_vals.threadid << " and doing " << chk_vals.nchecks << " checks" << endl;
#endif
		chk_vals.perm = (linking_t*) malloc(sizeof(linking_t) * chk_vals.nchecks);
		m_vSockets[csockid].Receive((BYTE*) chk_vals.perm, sizeof(linking_t) * chk_vals.nchecks);
#if CHECK_METHOD == 1
		//Receive the opened choice bits for the NNOB style OT extension
		chk_vals.permchoicebits = (BYTE*) malloc(sizeof(BYTE) * chk_vals.nchecks);
		m_vSockets[csockid].Receive(chk_vals.permchoicebits, sizeof(BYTE) * chk_vals.nchecks);
#endif

		chk_vals.outhashes = (BYTE*) calloc(chk_vals.nchecks * OWF_BYTES * RECEIVER_HASHES, sizeof(BYTE));

#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
		ComputeOWF(&chk_vals);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalCheckTime += getMillies(tempStart, tempEnd);
#endif
		m_vSockets[csockid].Send(chk_vals.outhashes, chk_vals.nchecks * OWF_BYTES * RECEIVER_HASHES);

		m_vSockets[csockid].Receive(&success, sizeof(BYTE));
		if(!success) {
			cerr << "Error in consistency check, aborting!" << endl;
			exit(0);
		}
#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif

		if(m_bProtocol == G_OT || m_bProtocol == C_OT || m_bProtocol == S_OT) {
			//cerr << " with " << processedOTs << " OTs ";
			rcvbytes = CEIL_DIVIDE(processedOTs * m_nBitLength, 8);
			if(m_bProtocol == G_OT)
				rcvbytes = rcvbytes*m_nSndVals;
			//cerr << "Receiving " << rcvbytes << " bytes" << endl;
			rcvbytes = m_vSockets[csockid].Receive(vRcv.GetArr(), rcvbytes);

			m_fMaskFct->UnMask(otid, processedOTs, m_nChoices, m_nRet, vRcv, m_vTempOTMasks, m_bProtocol);
#ifdef OTTiming
			gettimeofday(&tempEnd, NULL);
			totalUnmaskTime += getMillies(tempStart, tempEnd);
#endif
		}
 		progress += processedOTs;

 		free(chk_vals.perm);
 		free(chk_vals.outhashes);
#if CHECK_METHOD == 1
 		free(chk_vals.permchoicebits);
#endif
	}

#ifdef OTTiming
	cerr << "Total time spent processing received data: " << totalUnmaskTime << " ms" << endl;
	cerr << "Total time spent ensuring malicious security: " << totalCheckTime << " ms" << endl;
#endif

	vRcv.delCBitVector();
}

void Mal_OTExtensionReceiver::EnqueueSeed(BYTE* T0, BYTE* T1, int ctr, int numblocks) {
	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs) );
	int wd_size_bytes = wd_size_bits >> 3;
	int expseedbytelen = m_nBaseOTs * numblocks * wd_size_bytes;
	exp_seed_t* seedstr = (exp_seed_t*) malloc(sizeof(exp_seed_t));
	seedstr->blockid = ctr;
	seedstr->expstrbitlen = numblocks * wd_size_bytes * 8;
	seedstr->T0 = (BYTE*) malloc(expseedbytelen);
	seedstr->T1 = (BYTE*) malloc(expseedbytelen);
	seedstr->next = NULL;
	memcpy(seedstr->T0, T0, expseedbytelen);
	memcpy(seedstr->T1, T1, expseedbytelen);

	m_lSeedLock->Lock();
	if(m_tSeedHead == NULL) {
		m_tSeedHead = seedstr;
		m_tSeedTail = seedstr;
	} else {
		m_tSeedTail->next = seedstr;
		m_tSeedTail = seedstr;
	}
	//cerr << "added seed with blockid = " << ctr << endl;
	m_lSeedLock->Unlock();
}


void Mal_OTExtensionReceiver::ComputeOWF(rcv_check_t* chk_vals) {//linking_t* permbits, int nchecks, int otid, int processedOTs, BYTE* outhashes) {

	//Obtain T0 and T1 from the SeedPointers
	BOOL found = false;
	exp_seed_t *seedptr, *seedptrprev;
	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs));
	seedptr = m_tSeedHead;
	seedptrprev = NULL;

	m_lSeedLock->Lock();
	assert(seedptr != NULL);

	while(seedptr != m_tSeedTail && !found) {
		if(seedptr->blockid == chk_vals->otid)
			found = true;
		else {
			seedptrprev = seedptr;
			seedptr = seedptr->next;
		}
	}
	//the seeds have to exist
	assert(seedptr->blockid == chk_vals->otid);// && seedptr->expstrbitlen == PadToMultiple(processedOTs, wd_size_bits));
	//cerr << seedptr->expstrbitlen << ", vs. " << wd_size_bits << endl;
	//case A) is Head
	if(seedptr == m_tSeedHead) {
		m_tSeedHead = m_tSeedHead->next;
	} else if (seedptr == m_tSeedTail){ //case B) is Tail
		m_tSeedTail = seedptrprev;
		seedptrprev->next = NULL;
	} else { //case C) inbetween
		seedptrprev->next = seedptr->next;
	}

	m_lSeedLock->Unlock();

	//the bufsize has to be padded to a multiple of the PRF-size since we will omit boundary checks there
	int i, k, j, bufrowbytelen=seedptr->expstrbitlen>>3;//(CEIL_DIVIDE(processedOTs, wd_size_bits) * wd_size_bits) >>3;
	//contains the T-matrix
	BYTE* T0 = seedptr->T0;
	//contains the T-matrix XOR the receive bits
	BYTE* T1 = seedptr->T1;

	BYTE* T0ptr = T0;
	BYTE* T1ptr = T1;

#ifdef AES_OWF
	AES_KEY_CTX aesowfkey;
	MPC_AES_KEY_INIT(&aesowfkey);
#else
	BYTE* hash_buf = (BYTE*) malloc(sizeof(BYTE) * SHA1_BYTES);
#endif
	BYTE* tmpbuf = (BYTE*) malloc(bufrowbytelen);
	BYTE **ka = (BYTE**) malloc(sizeof(BYTE*) * 2);
	BYTE **kb = (BYTE**) malloc(sizeof(BYTE*) * 2);
	BYTE  *kaptr, *kbptr;
	BYTE* outptr = chk_vals->outhashes;
	int ida, idb;
	int rowbytelen = bufrowbytelen;//CEIL_DIVIDE(processedOTs, 8);

#if CHECK_METHOD == 0
	//cerr << "Checking" << endl;
	//Compute all hashes for the permutations given Ta and Tb
	for(i = 0; i < chk_vals->nchecks; i++) {
		ka[0] = T0 + chk_vals->perm[i].ida * bufrowbytelen;
		ka[1] = T1 + chk_vals->perm[i].ida * bufrowbytelen;

		kb[0] = T0 + chk_vals->perm[i].idb * bufrowbytelen;
		kb[1] = T1 + chk_vals->perm[i].idb * bufrowbytelen;
		//cerr << "ida = " << permbits[i].ida <<", idb= " <<  permbits[i].idb << endl;

		//XOR all four possibilities
	#ifdef DEBUG_MALICIOUS
		cerr << i << "-th check: between " << chk_vals->perm[i].ida << ", and " << chk_vals->perm[i].idb << endl;
	#endif
		for(j = 0; j < RECEIVER_HASHES; j++, outptr+=OWF_BYTES) {
			kaptr = ka[j>>1];
			kbptr = kb[j&0x01];

			for(k = 0; k < rowbytelen / sizeof(uint64_t); k++) {
				((uint64_t*) tmpbuf)[k] = ((uint64_t*) kaptr)[k] ^ ((uint64_t*) kbptr)[k];
			}
	#ifdef AES_OWF
			owf(&aesowfkey, rowbytelen, tmpbuf, outptr);
	#else
			owf(hash_buf, rowbytelen, tmpbuf, outptr);
	#endif
		}
	#ifdef DEBUG_MALICIOUS
		cerr << endl;
	#endif
	}
#else
	BYTE* sender_permchoicebits = chk_vals->permchoicebits;
	BYTE* receiver_choicebits = m_nChoices.GetArr() + CEIL_DIVIDE(chk_vals->otid, 8);
	CBitVector tmp;
	tmp.AttachBuf(tmpbuf, bufrowbytelen*8);
	//cerr << "Choice bits: " << endl;
	//m_nChoices.PrintHex();
	//cerr << "Checking" << endl;
	//Compute all hashes for the permutations given Ta, Tb and the choice bits
	for(i = 0; i < chk_vals->nchecks; i++, sender_permchoicebits++) {
		ka[0] = T0 + chk_vals->perm[i].ida * bufrowbytelen;
		kb[0] = T0 + chk_vals->perm[i].idb * bufrowbytelen;

		//cerr << "ida = " << permbits[i].ida <<", idb= " <<  permbits[i].idb << endl;

		//XOR all four possibilities
	#ifdef DEBUG_MALICIOUS
		cerr << (dec) << i << "-th check: between " << chk_vals->perm[i].ida << ", and " << chk_vals->perm[i].idb << endl;
	#endif
		for(j = 0; j < RECEIVER_HASHES; j++, outptr+=OWF_BYTES) {
			kaptr = ka[0];
			kbptr = kb[0];

			assert((*sender_permchoicebits) == 0 || (*sender_permchoicebits == 1));

			tmp.SetXOR(kaptr, kbptr, 0, rowbytelen);
			if((*sender_permchoicebits == 1)) {
				tmp.XORBytesReverse(receiver_choicebits, 0, rowbytelen);
			}

	#ifdef AES_OWF
			owf(&aesowfkey, rowbytelen, tmpbuf, outhashes);
	#else
			owf(hash_buf, rowbytelen, tmpbuf, outptr);
	#endif
		}
	#ifdef DEBUG_MALICIOUS
		cerr << endl;
	#endif
	}
#endif

	//cerr << "Finishing check" << endl;
	free(tmpbuf);
	free(ka);
	free(kb);
	free(seedptr->T0);
	free(seedptr->T1);
	free(seedptr);
#ifndef AES_OWF
	free(hash_buf);
#endif
}





BOOL Mal_OTExtensionReceiver::verifyOT(int NumOTs)
{
	CSocket sock = m_vSockets[0];
	CBitVector vRcvX0(NUMOTBLOCKS*AES_BITS*m_nBitLength);
	CBitVector vRcvX1(NUMOTBLOCKS*AES_BITS*m_nBitLength);
	CBitVector* Xc;
	int processedOTBlocks, OTsPerIteration;
	int bytelen = CEIL_DIVIDE(m_nBitLength, 8);
	BYTE* tempXc = (BYTE*) malloc(bytelen);
	BYTE* tempRet = (BYTE*) malloc(bytelen);
	BYTE resp;
	for(int i = 0; i < NumOTs;)
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(NumOTs-i, AES_BITS));
		OTsPerIteration = min(processedOTBlocks * AES_BITS, NumOTs-i);
		sock.Receive(vRcvX0.GetArr(), CEIL_DIVIDE(m_nBitLength * OTsPerIteration, 8));
		sock.Receive(vRcvX1.GetArr(), CEIL_DIVIDE(m_nBitLength * OTsPerIteration, 8));
		for(int j = 0; j < OTsPerIteration && i < NumOTs; j++, i++)
		{
			if(m_nChoices.GetBitNoMask(i) == 0) Xc = &vRcvX0;
			else Xc = &vRcvX1;

			Xc->GetBits(tempXc, j*m_nBitLength, m_nBitLength);
			m_nRet.GetBits(tempRet, i*m_nBitLength, m_nBitLength);
			for(int k = 0; k < bytelen; k++)
			{
				if(tempXc[k] != tempRet[k])
				{
					cerr << "Error at position i = " << i << ", k = " << k << ", with X" << (hex) << (unsigned int) m_nChoices.GetBitNoMask(i)
							<< " = " << (unsigned int) tempXc[k] << " and res = " << (unsigned int) tempRet[k] << (dec) << endl;
					resp = 0x00;
					sock.Send(&resp, 1);
					return false;
				}
			}
		}
		resp = 0x01;
		sock.Send(&resp, 1);
	}
	free(tempXc);
	free(tempRet);

	vRcvX0.delCBitVector();
	vRcvX1.delCBitVector();


	//cerr << "OT Verification successful" << endl;
	return true;
}



BOOL Mal_OTExtensionSender::send(int numOTs, int bitlength, CBitVector& x0, CBitVector& x1, BYTE type,
		int numThreads, MaskingFunction* maskfct)
{
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_vValues[0] = x0;
	m_vValues[1] = x1;
	m_bProtocol = type;
	m_fMaskFct = maskfct;
	return send(numThreads);
}


//Initialize and start numThreads OTSenderThread
BOOL Mal_OTExtensionSender::send(int numThreads)
{
	if(m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs));
	int numOTs = CEIL_DIVIDE(PadToMultiple(m_nOTs, wd_size_bits), numThreads);
	m_nBlocks = 0;
	m_lSendLock = new CLock;


	vector<OTSenderThread*> sThreads(numThreads);

	//one AES_BYTES - bytes reply-check-buf and seed-check-buf for every sending thread and for every check
	m_vRcvCheckBuf = (BYTE**) malloc(sizeof(BYTE*) * numThreads);
	m_vSeedCheckBuf = (BYTE**) malloc(sizeof(BYTE*) * numThreads);
	//memory for the permutation that is used for checking
	m_tPermCheck = (linking_t**) malloc(sizeof(linking_t*) * numThreads);

	for(int i = 0; i < numThreads; i++) {
		m_vRcvCheckBuf[i] = (BYTE*) calloc(m_nChecks * OWF_BYTES, sizeof(BYTE));
		m_vSeedCheckBuf[i] = (BYTE*) calloc(m_nChecks * OWF_BYTES, sizeof(BYTE));
		m_tPermCheck[i] = (linking_t*) malloc(sizeof(linking_t) * m_nChecks);
	}
	//BYTE go;
	//sock.Send(&go, 1);

	for(int i = 0; i < numThreads; i++) 	{
		sThreads[i] = new OTSenderThread(i, numOTs, this);
		sThreads[i]->Start();
	}
	
	SendBlocks(numThreads);

	for(int i = 0; i < numThreads; i++) 	{
		sThreads[i]->Wait();
	}

	m_nCounter += m_nOTs;

	for(int i = 0; i < numThreads; i++) {
		free(m_vRcvCheckBuf[i]);
		free(m_vSeedCheckBuf[i]);
		free(m_tPermCheck[i]);
		delete sThreads[i];
	}

	free(m_vRcvCheckBuf);
	free(m_vSeedCheckBuf);
	free(m_tPermCheck);

#ifdef VERIFY_OT
	BYTE finished;
	m_vSockets[0].Receive(&finished, 1);

	verifyOT(m_nOTs);
#endif

	return true;
}


BOOL Mal_OTExtensionSender::OTSenderRoutine(int id, int myNumOTs)
{
	CSocket sock = m_vSockets[id];

	int nProgress;
	int myStartPos = id * myNumOTs; 
	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs));
	int processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(myNumOTs, wd_size_bits));
	int OTsPerIteration = processedOTBlocks * wd_size_bits;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	int lim = myStartPos+myNumOTs;

	if(m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
		m_nSndVals = 1;

	// The vector with the received bits
	CBitVector vRcv(m_nBaseOTs * OTsPerIteration);
		
	// Holds the reply that is sent back to the receiver
	int numsndvals = 2;
	CBitVector* vSnd;

	/*if(m_bProtocol == G_OT) numsndvals = 2;
	else if (m_bProtocol == C_OT || m_bProtocol == S_OT) numsndvals = 1;
	else numsndvals = 0;*/

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for(int u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration* AES_KEY_BITS);
#ifdef ZDEBUG
	cerr << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << endl;
#endif
	vSnd = new CBitVector[numsndvals];//(CBitVector*) malloc(sizeof(CBitVector) * numsndvals);
	for(int i = 0; i < numsndvals; i++) 	{
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Contains the parts of the V matrix
	CBitVector Q(wd_size_bits * OTsPerIteration);
	
	// A buffer that holds a counting value, required for a faster interaction with the AES calls
	BYTE ctr_buf[AES_BYTES];
	memset(ctr_buf, 0, AES_BYTES);
	int* counter = (int*) ctr_buf;
	counter[0] = myStartPos + m_nCounter;

	snd_check_t chk_vals;
#if CHECK_METHOD == 0
	chk_vals.rcv_chk_buf = m_vRcvCheckBuf[id];
	chk_vals.seed_chk_buf = m_vSeedCheckBuf[id];
#else
	chk_vals.chk_buf = m_vRcvCheckBuf[id];
#endif
	chk_vals.perm = m_tPermCheck[id];



	nProgress = myStartPos;

	genRandomPermutation(chk_vals.perm, m_nBaseOTs, m_nChecks, nProgress);

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while( nProgress < lim ) //do while there are still transfers missing
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(lim-nProgress, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;

#ifdef ZDEBUG
		cerr << "Processing block " << nProgress << " with length: " << OTsPerIteration << ", and limit: " << lim << endl;
#endif

#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
		sock.Receive(vRcv.GetArr(), CEIL_DIVIDE(m_nBaseOTs*OTsPerIteration,8));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalRcvTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		BuildQMatrix(Q, vRcv, processedOTBlocks, ctr_buf, &chk_vals);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalMtxTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		Q.EklundhBitTranspose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
		MaskInputs(Q, seedbuf, vSnd, nProgress, min(lim-nProgress, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalHshTime += getMillies(tempStart, tempEnd);
 		gettimeofday(&tempStart, NULL);
#endif
 		ProcessAndEnqueue(vSnd, id, nProgress, min(lim-nProgress, OTsPerIteration));
#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		(*counter) += min(lim-nProgress, OTsPerIteration);
		nProgress += min(lim-nProgress, OTsPerIteration);
		Q.Reset();
	}

	vRcv.delCBitVector();
	Q.delCBitVector();
	for(int u = 0; u < m_nSndVals; u++)
		seedbuf[u].delCBitVector();

	for(int i = 0; i < numsndvals; i++)
		vSnd[i].delCBitVector();
	if(numsndvals > 0)	free(vSnd);

#ifdef OTTiming
	cerr << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cerr << "Time needed for: " << endl;
	cerr << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cerr << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cerr << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cerr << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cerr << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

#ifndef BATCH
	//cerr << "Sender finished successfully" << endl;
#endif
	return TRUE;
}

void Mal_OTExtensionSender::BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, int numblocks, BYTE* ctr_buf,
		snd_check_t* check_vals) //BYTE* seed_check_buf, BYTE* rcv_check_buf, linking_t* permbits)
{
	BYTE* rcvbufptr = RcvBuf.GetArr();
	BYTE* Tptr = T.GetArr();
	int dummy;
	int* counter = (int*) ctr_buf;
	int tempctr = *counter;
	int wd_size_bytes = 1 << (CEIL_LOG2(m_nBaseOTs) -3);
	int rowbytelen = wd_size_bytes * numblocks;
	//cerr << "counter =  " << (dec) << tempctr << endl;

	AES_KEY_CTX* seedptr = m_vKeySeeds;
	int otid = (*counter) - m_nCounter;
	//How many blocks have been processed until now
	int blockoffset = CEIL_DIVIDE(otid, NUMOTBLOCKS * wd_size_bytes * 8);
	int offset = m_nBaseOTs * blockoffset;
	//cerr << "Using block: " << blockoffset << ", counter = " << *counter << ", wdsize = " << wd_size_bytes*8 << "; ctr = " << m_nCounter << endl;
	seedptr += (offset);


	for (int k = 0; k < m_nBaseOTs; k++, rcvbufptr += rowbytelen) 	{
		for(int b = 0; b < rowbytelen / AES_BYTES; b++, (*counter)++, Tptr += AES_BYTES) {
			MPC_AES_ENCRYPT(seedptr + k, Tptr, ctr_buf);
#ifdef DEBUG_MALICIOUS
			cerr << "k = " << k << ": "<< (hex) << ((uint64_t*) Tptr)[0] << ((uint64_t*) Tptr)[1] << (hex) << endl;
#endif

		}
		*counter = tempctr;
	}

	UpdateCheckBuf(T.GetArr(), RcvBuf.GetArr(), otid, rowbytelen, check_vals);

	//XOR m_nU on top
	rcvbufptr = RcvBuf.GetArr();
	for (int k = 0; k < m_nBaseOTs; k++, rcvbufptr += rowbytelen) 	{
		if(m_vU.GetBit(k+offset))	{
			T.XORBytes(rcvbufptr, k*rowbytelen, rowbytelen);
		}
	}
}

void Mal_OTExtensionSender::UpdateCheckBuf(BYTE* tocheckseed, BYTE* tocheckrcv, int otid, int rowbytelen, snd_check_t* check_vals) {
	AES_KEY_CTX aesowfkey;
	MPC_AES_KEY_INIT(&aesowfkey);
	BYTE* hash_buf = (BYTE*) malloc(sizeof(BYTE) * SHA1_BYTES);
	BYTE* tmpbuf = (BYTE*) malloc(sizeof(BYTE) * rowbytelen);
	//BYTE* inbuf = (BYTE*) malloc(sizeof(BYTE) * OWF_BYTES);
	BYTE *idaptr, *idbptr;
#if CHECK_METHOD == 0
	BYTE *seedcheckbufptr= check_vals->seed_chk_buf, *rcvcheckbufptr = check_vals->rcv_chk_buf;
#else
	BYTE *chk_buf_ptr= check_vals->chk_buf;
	BYTE *idatmpbuf = (BYTE*) malloc(sizeof(BYTE) * rowbytelen);
	BYTE *idbtmpbuf = (BYTE*) malloc(sizeof(BYTE) * rowbytelen);
	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs));
	int blockoffset = CEIL_DIVIDE(otid, NUMOTBLOCKS * wd_size_bits);
#endif

	int i, k;

	//right now the rowbytelen needs to be a multiple of AES_BYTES
	assert(CEIL_DIVIDE(rowbytelen, OWF_BYTES) * OWF_BYTES == rowbytelen);
#ifdef DEBUG_MALICIOUS
	cerr << "rowbytelen = " << rowbytelen << endl;
	m_vU.PrintHex();
#endif

#if CHECK_METHOD == 0
	for(i = 0; i < m_nChecks; i++, seedcheckbufptr+=OWF_BYTES, rcvcheckbufptr+=OWF_BYTES) {
		memset(tmpbuf, 0, sizeof(BYTE) * rowbytelen);
		XORandOWF(tocheckseed + check_vals->perm[i].ida * rowbytelen, tocheckseed + check_vals->perm[i].idb * rowbytelen,
				rowbytelen, tmpbuf, seedcheckbufptr, hash_buf);
		XORandOWF(tocheckrcv + check_vals->perm[i].ida * rowbytelen, tocheckrcv + check_vals->perm[i].idb * rowbytelen,
				rowbytelen, tmpbuf, rcvcheckbufptr, hash_buf);
	}
#else
	for(i = 0; i < m_nChecks; i++, chk_buf_ptr+=OWF_BYTES) {
	#ifdef DEBUG_MALICIOUS
		cerr << "ca: "  << (unsigned int) m_vU.GetBit(blockoffset * m_nBaseOTs + check_vals->perm[i].ida) <<
				", cb: " << (unsigned int) m_vU.GetBit(blockoffset * m_nBaseOTs + check_vals->perm[i].idb) << endl;
	#endif
		memset(tmpbuf, 0, sizeof(BYTE) * rowbytelen);
		if(m_vU.GetBit(blockoffset * m_nBaseOTs + check_vals->perm[i].ida) == 0) {
			memcpy(idatmpbuf, tocheckseed + check_vals->perm[i].ida * rowbytelen, rowbytelen);
		} else {
			BYTE* seedptr = tocheckseed + check_vals->perm[i].ida * rowbytelen;
			BYTE* rcvptr = tocheckrcv + check_vals->perm[i].ida * rowbytelen;
			for(int j = 0; j < rowbytelen/sizeof(uint64_t); j++) {
				((uint64_t*) idatmpbuf)[j] = ((uint64_t*) seedptr)[j] ^ ((uint64_t*) rcvptr)[j];
			}
		}

		if(m_vU.GetBit(blockoffset * m_nBaseOTs + check_vals->perm[i].idb) == 0) {
			memcpy(idbtmpbuf, tocheckseed + check_vals->perm[i].idb * rowbytelen, rowbytelen);
		} else {
			BYTE* seedptr = tocheckseed + check_vals->perm[i].idb * rowbytelen;
			BYTE* rcvptr = tocheckrcv + check_vals->perm[i].idb * rowbytelen;
			for(int j = 0; j < rowbytelen/sizeof(uint64_t); j++) {
				((uint64_t*) idbtmpbuf)[j] = ((uint64_t*) seedptr)[j] ^ ((uint64_t*) rcvptr)[j];
			}
		}

	#ifdef DEBUG_MALICIOUS
		cerr << "seedA: " <<  (hex) << ((uint64_t*) (tocheckseed + check_vals->perm[i].ida * rowbytelen))[0] << ", rcvA: " << ((uint64_t*) (tocheckrcv + check_vals->perm[i].ida * rowbytelen))[0] << (dec) << endl;
		cerr << "seedB: " <<  (hex) << ((uint64_t*) (tocheckseed + check_vals->perm[i].idb * rowbytelen))[0] << ", rcvB: " << ((uint64_t*) (tocheckrcv + check_vals->perm[i].idb * rowbytelen))[0] << (dec) << endl;
		cerr << "input to owf " <<  (hex) << ((uint64_t*) idatmpbuf)[0] << ", " << ((uint64_t*) idbtmpbuf)[0] << (dec) << endl;
	#endif

		XORandOWF(idatmpbuf, idbtmpbuf,	rowbytelen, tmpbuf, chk_buf_ptr, hash_buf);
	}
#endif


	free(tmpbuf);
	free(hash_buf);

#if CHECK_METHOD == 1
	free(idatmpbuf);
	free(idbtmpbuf);
#endif
}

inline void Mal_OTExtensionSender::XORandOWF(BYTE* idaptr, BYTE* idbptr, int rowbytelen, BYTE* tmpbuf, BYTE* resbuf, BYTE* hash_buf) {
	AES_KEY_CTX aesowfkey;
	MPC_AES_KEY_INIT(&aesowfkey);

	for(int j = 0; j < rowbytelen/sizeof(uint64_t); j++) {
		((uint64_t*) tmpbuf)[j] = ((uint64_t*) tmpbuf)[j] ^ ((uint64_t*) idaptr)[j] ^ ((uint64_t*) idbptr)[j];
	}

#ifdef AES_OWF
		owf(&aesowfkey, rowbytelen, tmpbuf, resbuf);
#else
		owf(hash_buf, rowbytelen, tmpbuf, resbuf);
#endif
}


void Mal_OTExtensionSender::MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, int ctr, int processedOTs)
{
	int numhashiters = CEIL_DIVIDE(m_nBitLength, SHA1_BITS);
	int hashinbytelen = CEIL_DIVIDE(m_nBaseOTs, 8);
	int wd_size_bytes = 1 << (CEIL_LOG2(m_nBaseOTs) -3);
	//How many blocks have been processed until now
	int blockoffset = CEIL_DIVIDE(ctr, NUMOTBLOCKS * wd_size_bytes * 8);
	int offset = blockoffset * m_nBaseOTs;

	HASH_CTX sha, shatmp;
	BYTE hash_buf[SHA1_BYTES];

	BYTE* Qptr = Q.GetArr();
	CBitVector Utmp(m_nBaseOTs);
	BYTE* Utmpptr= Utmp.GetArr(); //(BYTE*) calloc(hashinbytelen, sizeof(BYTE));

	//m_vU.GetBits(Uptr, blockoffset * m_nBaseOTs, m_nBaseOTs);
	//Uptr=m_vU.GetArr();
	for(int i = 0; i < m_nBaseOTs; i++)
		Utmp.SetBit(i, m_vU.GetBit(i+offset));

	BYTE** sbp = new BYTE*[m_nSndVals];


	for(int u = 0; u < m_nSndVals; u++)
		sbp[u] = seedbuf[u].GetArr();

	for(int i = ctr, j = 0; j<processedOTs; i++, j++)
	{
		if(m_bProtocol == OCRS_OT && m_vValues[0].GetBitNoMask(i) == 0)
		{
			continue;
		}

#ifndef FIXED_KEY_AES_HASHING
		MPC_HASH_INIT(&sha);
		MPC_HASH_UPDATE(&sha, (BYTE*) &i, sizeof(i));

		shatmp = sha;
#endif
		for(int u = 0; u < m_nSndVals; u++)
		{
			//omit zero possibility
			//if( || m_bProtocol == OCRS_OT)
			//	Q.XORBytes(m_nU.GetArr(), j * OTEXT_BLOCK_SIZE_BYTES, m_nSymSecParam>>3);


			if(u == 1 || m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
				Q.XORBytes(Utmpptr, j * wd_size_bytes, hashinbytelen);

#ifdef OT_HASH_DEBUG
			cerr << "Hash-In for i = " << i << ", u = " << u << ": " << (hex);
			for(int p = 0; p < hashinbytelen; p++)
				cerr << (unsigned int) (Q.GetArr() + j * wd_size_bytes)[p];
			cerr << (dec) << endl;
#endif

#ifdef FIXED_KEY_AES_HASHING
			//AES_KEY_CTX* aeskey, BYTE* outbuf, BYTE* inbuf, BYTE* tmpbuf, int id, int bytessecparam
			FixedKeyHashing(m_kCRFKey, sbp[u], Q.GetArr() + j * wd_size_bytes, hash_buf, i, hashinbytelen);
#else
			sha = shatmp;

			MPC_HASH_UPDATE(&sha, Q.GetArr()+ j * wd_size_bytes, hashinbytelen);
			MPC_HASH_FINAL(&sha, hash_buf);

			memcpy(sbp[u], hash_buf, AES_KEY_BYTES);
#endif

			//cerr << ((unsigned int) sbp[u][0] & 0x01);
			sbp[u] += AES_KEY_BYTES;

			if(m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
			{
				u=m_nSndVals-1;
			}
		}
	}

	if(m_bProtocol == S_OT || m_bProtocol == OCRS_OT)
	{
		m_fMaskFct->expandMask(snd_buf[0], seedbuf[0].GetArr(), 0, processedOTs, m_nBitLength);
		return;
	}

	//Two calls to expandMask, both writing into snd_buf
	for(int u = 0; u < m_nSndVals; u++)
		m_fMaskFct->expandMask(snd_buf[u], seedbuf[u].GetArr(), 0, processedOTs, m_nBitLength);

	Utmp.delCBitVector();
}





void Mal_OTExtensionSender::ProcessAndEnqueue(CBitVector* snd_buf, int id, int progress, int processedOTs)
{
#if CHECK_METHOD == 1
	int wd_size_bits= 1 << (CEIL_LOG2(m_nBaseOTs));
	int blockid = CEIL_DIVIDE(progress, wd_size_bits * NUMOTBLOCKS);
#endif
	m_fMaskFct->Mask(progress, processedOTs, m_vValues, snd_buf, m_bProtocol);

	//if(m_bProtocol == R_OT)
	//	return;

	OTBlock* block = new OTBlock;
	int bufsize = CEIL_DIVIDE(processedOTs * m_nBitLength, 8);

	block->blockid = progress;
	block->processedOTs = processedOTs;
	block->threadid = id;
	block->perm = (linking_t*) malloc(sizeof(linking_t) * m_nChecks);
#if CHECK_METHOD == 0
	block->seed_hash = (BYTE*) malloc(sizeof(BYTE) * OWF_BYTES * m_nChecks);
	block->rcv_hash = (BYTE*) malloc(sizeof(BYTE) * OWF_BYTES * m_nChecks);
#else
	block->hash_buf = (BYTE*) malloc(sizeof(BYTE) * OWF_BYTES * m_nChecks);
	//Send the XORed bits of the base OTs
	block->permchoicebits = (BYTE*) malloc(sizeof(BYTE) * m_nChecks);
#endif

	memcpy(block->perm, m_tPermCheck[id], sizeof(linking_t) * m_nChecks);
#if CHECK_METHOD == 0
	memcpy(block->seed_hash, m_vSeedCheckBuf[id], OWF_BYTES * m_nChecks);
	memcpy(block->rcv_hash, m_vRcvCheckBuf[id], OWF_BYTES * m_nChecks);
	memset(m_vSeedCheckBuf[id], 0x00, OWF_BYTES * m_nChecks);
#else
	memcpy(block->hash_buf, m_vRcvCheckBuf[id], OWF_BYTES * m_nChecks);
	//Store the XORed choice bits for the permutation
	for(int i = 0; i < m_nChecks; i++) {
		block->permchoicebits[i] = m_vU.GetBit(blockid * m_nBaseOTs + block->perm[i].ida) ^ m_vU.GetBit(blockid * m_nBaseOTs + block->perm[i].idb);
	}
#endif

	memset(m_vRcvCheckBuf[id], 0x00, OWF_BYTES * m_nChecks);

	//choose new permutation
	genRandomPermutation(m_tPermCheck[id], m_nBaseOTs, m_nChecks, progress + processedOTs);

	if(m_bProtocol == G_OT)
	{
		block->snd_buf = new BYTE[bufsize<<1];
		memcpy(block->snd_buf, snd_buf[0].GetArr(), bufsize);
		memcpy(block->snd_buf+bufsize, snd_buf[1].GetArr(), bufsize);
	}
	else if(m_bProtocol == C_OT)
	{
		block->snd_buf = new BYTE[bufsize];
		memcpy(block->snd_buf, snd_buf[1].GetArr(), bufsize);
	}
	else if(m_bProtocol == S_OT)
	{
		block->snd_buf = new BYTE[bufsize];
		memcpy(block->snd_buf, snd_buf[0].GetArr(), bufsize);
	}

	m_lSendLock->Lock();
	//Lock this part if multiple threads are used!
	if(m_nBlocks == 0)
	{
		m_sBlockHead = block;
		m_sBlockTail = block;
	} else {
		m_sBlockTail->next = block;
		m_sBlockTail = block;
	}
	m_nBlocks++;
	m_lSendLock->Unlock();
}


void Mal_OTExtensionSender::SendBlocks(int numThreads)
{
	OTBlock* tempBlock;
	int progress = 0;
	int rcvhashbytes = RECEIVER_HASHES * m_nChecks * OWF_BYTES, csockid=numThreads;
	BYTE* rcvhashbuf;
	BYTE success;


#ifdef OTTiming
	double totalTnsTime = 0;
	timeval tempStart, tempEnd;
#endif

	while(progress < m_nOTs)
	{
		if(m_nBlocks > 0)
		{
#ifdef OTTiming
 		gettimeofday(&tempStart, NULL);
#endif
			tempBlock = m_sBlockHead;
			//send: blockid, #processedOTs, threadid, #checks, permbits
			m_vSockets[csockid].Send((BYTE*) &(tempBlock->blockid), sizeof(int));
			m_vSockets[csockid].Send((BYTE*) &(tempBlock->processedOTs), sizeof(int));
			m_vSockets[csockid].Send((BYTE*) &(tempBlock->threadid), sizeof(int));
			m_vSockets[csockid].Send((BYTE*) &m_nChecks, sizeof(int));
			m_vSockets[csockid].Send((BYTE*) tempBlock->perm, sizeof(linking_t) * m_nChecks);
#if CHECK_METHOD == 1
			m_vSockets[csockid].Send((BYTE*) tempBlock->permchoicebits, sizeof(BYTE) * m_nChecks);
#endif
#ifdef DEBUG_MALICIOUS
			cerr << "Want to check otid = " << tempBlock->blockid << " of len " << tempBlock->processedOTs << " for thread "
					<< tempBlock->threadid << " and doing " << m_nChecks << " checks" << endl;
#endif
			//wait for reply and check values
			rcvhashbuf = (BYTE*) malloc(rcvhashbytes);
			m_vSockets[csockid].Receive(rcvhashbuf, rcvhashbytes);

			success = CheckConsistentReceiveBits(rcvhashbuf, tempBlock);
			success = true;

			m_vSockets[csockid].Send(&success, 1);
			if(!success) {
				cerr << "Error in consistency check for block " << tempBlock->blockid << ", receiver possibly malicious, aborting OT extension!" << endl;
				exit(0);
			} else {
#ifdef DEBUG_MALICIOUS
				cerr << "Consistency check for block " << tempBlock->blockid << " ok" << endl;
#endif
			}

			if(m_bProtocol == G_OT)
			{
				m_vSockets[csockid].Send(tempBlock->snd_buf, 2*CEIL_DIVIDE((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			else if(m_bProtocol == C_OT)
			{
				m_vSockets[csockid].Send(tempBlock->snd_buf, CEIL_DIVIDE((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			else if(m_bProtocol == S_OT)
			{
				m_vSockets[csockid].Send(tempBlock->snd_buf, CEIL_DIVIDE((tempBlock->processedOTs) * m_nBitLength, 8));
			}

			m_sBlockHead = m_sBlockHead->next;

			//Lock this part
			m_lSendLock->Lock();
			m_nBlocks--;
			m_lSendLock->Unlock();

			progress += tempBlock->processedOTs;
			if(m_bProtocol != R_OT && m_bProtocol != OCRS_OT)
				delete tempBlock->snd_buf;
			free(tempBlock->perm);
#if CHECK_METHOD == 0
			free(tempBlock->seed_hash);
			free(tempBlock->rcv_hash);
#else
			free(tempBlock->hash_buf);
			free(tempBlock->permchoicebits);
#endif
			delete tempBlock;

#ifdef OTTiming
 		gettimeofday(&tempEnd, NULL);
 		totalTnsTime += getMillies(tempStart, tempEnd);
#endif
		}
	}
#ifdef OTTiming
	cerr << "Total time spent transmitting data: " << totalTnsTime << endl;
#endif
}

//check the consistency in the receivers choice bits to obtain malicious security
BOOL Mal_OTExtensionSender::CheckConsistentReceiveBits(BYTE* rcvhashbuf, OTBlock* block) {
#if CHECK_METHOD == 0
	BYTE *rcvhashbufptr, *seedbufsrvptr, *rcvbufsrvptr;
	int checkbytelen= RECEIVER_HASHES * OWF_BYTES;
	int i, j, ida, idb;

	int wd_size_bits = 1 << (CEIL_LOG2(m_nBaseOTs));
	int blockoffset = CEIL_DIVIDE(block->blockid, NUMOTBLOCKS * wd_size_bits);
	int offset = m_nBaseOTs * blockoffset;

	BYTE ca, cb;//, seedhashcli, rcvhashcli;
	uint64_t seedhashcli, rcvhashcli;
	rcvhashbufptr = rcvhashbuf;

	seedbufsrvptr = block->seed_hash;
	rcvbufsrvptr = block->rcv_hash;

	for(i = 0; i < m_nChecks; i++, rcvhashbufptr+=checkbytelen) {
		ida = block->perm[i].ida;
		idb = block->perm[i].idb;
		assert(ida < m_nBaseOTs && idb < m_nBaseOTs);

		ca = m_vU.GetBit(ida + offset);
		cb = m_vU.GetBit(idb + offset);

		//check that ida+idb == seedbufcheck and (!ida) + (!idb) == rcvbufcheck
		for(j = 0; j < OWF_BYTES/sizeof(uint64_t); j++, seedbufsrvptr+=sizeof(uint64_t), rcvbufsrvptr+=sizeof(uint64_t)) {

			seedhashcli = *(((uint64_t*) rcvhashbufptr) + (2*ca+cb)*2 + j);
			rcvhashcli = *(((uint64_t*) rcvhashbufptr) + (2*(ca^1)+(cb^1))*2 + j);


			if(seedhashcli != *((uint64_t*) seedbufsrvptr) || rcvhashcli != *((uint64_t*) rcvbufsrvptr)) {
	#ifdef DEBUG_MALICIOUS
				cerr << "Error in " << i <<"-th consistency check: " << endl;
				cerr << "Receiver seed = " << (hex) << ((uint64_t*) (rcvhashbufptr+((2*ca+cb) * OWF_BYTES)))[0] <<
						((uint64_t*) (rcvhashbufptr+((2*ca+cb) * OWF_BYTES) + j))[1] << ", my seed: " <<
						((uint64_t*) seedbufsrvptr)[0] << ((uint64_t*) seedbufsrvptr)[1] << (dec) << endl;
				cerr << "Receiver sndval = " << (hex) << ((uint64_t*) (rcvhashbufptr+((2*(ca^1)+(cb^1)) * OWF_BYTES) + j))[0] <<
						((uint64_t*) (rcvhashbufptr+((2*(ca^1)+(cb^1)) * OWF_BYTES) + j))[1] << ", my snd val = " <<
						((uint64_t*) rcvbufsrvptr)[0] << ((uint64_t*) rcvbufsrvptr)[1] << (dec) << endl;
	#endif
				return FALSE;
			}
		}
	}
#else
	//Very simple : just go over both arrays and check equality
	uint64_t* rcvbufptr = (uint64_t*) rcvhashbuf;
	uint64_t* chkbufptr = (uint64_t*) block->hash_buf;
	for(int i = 0; i < m_nChecks; i++) {
		for(int j = 0; j < OWF_BYTES /sizeof(uint64_t); j++, rcvbufptr++, chkbufptr++) {
			if(*rcvbufptr != *chkbufptr) {
	#ifdef DEBUG_MALICIOUS
				cerr << "Error in " << i <<"-th consistency check: " << endl;
				cerr << "Receiver hash = " << (hex) << *rcvbufptr << ", my hash: " << *chkbufptr << endl;
	#endif
				return FALSE;
			}
		}
	}
#endif

	return TRUE;

}

BOOL Mal_OTExtensionSender::verifyOT(int NumOTs)
{
	CSocket sock = m_vSockets[0];
	CBitVector vSnd(NUMOTBLOCKS*AES_BITS*m_nBitLength);
	int processedOTBlocks, OTsPerIteration;
	int bytelen = CEIL_DIVIDE(m_nBitLength, 8);
	int nSnd;
	BYTE resp;
	for(int i = 0; i < NumOTs;i+=OTsPerIteration)
	{
		processedOTBlocks = min(NUMOTBLOCKS, CEIL_DIVIDE(NumOTs-i, AES_BITS));
 		OTsPerIteration = min(processedOTBlocks * AES_BITS, NumOTs-i);
 		nSnd = CEIL_DIVIDE(OTsPerIteration * m_nBitLength, 8);
 		//cerr << "copying " << nSnd << " bytes from " << CEIL_DIVIDE(i*m_nBitLength, 8) << ", for i = " << i << endl;
 		vSnd.Copy(m_vValues[0].GetArr() + CEIL_DIVIDE(i*m_nBitLength, 8), 0, nSnd);
 		sock.Send(vSnd.GetArr(), nSnd);
 		vSnd.Copy(m_vValues[1].GetArr() + CEIL_DIVIDE(i*m_nBitLength, 8), 0, nSnd);
 		sock.Send(vSnd.GetArr(), nSnd);
		sock.Receive(&resp, 1);
		if(resp == 0x00)
		{
			cerr << "OT verification unsuccessful" << endl;
			return false;
		}
	}
	vSnd.delCBitVector();
	//cerr << "OT Verification successful" << endl;
	return true;
}

#ifdef AES_OWF
inline void owf(AES_KEY_CTX* aesowfkey, int rowbytelen, BYTE* msg, BYTE* H) {
#else
inline void owf(BYTE* hash_buf, int rowbytelen, BYTE* msg, BYTE* H) {
#endif

#ifdef AES_OWF
	BYTE* msgptr = msg;
	int i, j;

	#ifdef DEBUG_MALICIOUS
	for(i = 0; i < OWF_BYTES; i++)
		assert(H[i] == 0);
	#endif
	for(i = 0; i < rowbytelen; i+=OWF_BYTES, msgptr+=OWF_BYTES) {

		//cerr << "Expanding" << endl;
		MPC_AES_KEY_EXPAND(aesowfkey, H);

		//cerr << "encrypting" << endl;
		MPC_AES_ENCRYPT(aesowfkey, H, msgptr);

		xor_128_buf(H, H, msgptr);
	}
#else
	HASH_CTX sha;

	MPC_HASH_INIT(&sha);
	MPC_HASH_UPDATE(&sha, msg, rowbytelen);
	MPC_HASH_FINAL(&sha, hash_buf);
	memcpy(H, hash_buf, OWF_BYTES);
#endif

#ifdef DEBUG_MALICIOUS
	cerr << "owf for " << rowbytelen << " bytes of " << (hex) << ((uint64_t*) msg)[0] << ((uint64_t*) msg)[1] << (dec) << " = ";
	cerr <<  (hex) << ((uint64_t*) H)[0] << ((uint64_t*) H)[1] << (dec) << endl;
#endif

}


inline void Mal_OTExtensionSender::genRandomPermutation(linking_t* outperm, int nids, int nperms, int ctr) {
	int rndbits = m_nSymSecParam * nperms;
	int tmpctr = ctr;
	int bitsint = (8*sizeof(int));
	int lim = CEIL_DIVIDE(m_nSymSecParam, bitsint);
	CBitVector rndstring;
	rndstring.Create(lim * nperms, bitsint, m_vPermSeed, tmpctr);

	uint64_t tmpval, tmprnd;

	for(int i = 0, rndctr=0, j; i < nperms; i++) {
		outperm[i].ida = i % nids;
		for(j = 0, tmpval = 0; j < lim; j++, rndctr++) {
			tmprnd = rndstring.Get<uint64_t>(rndctr),
			tmpval = ((uint64_t) (tmprnd << bitsint) | tmpval);
			tmpval = tmpval % nids;

		}
		outperm[i].idb = (int) tmpval;
		//cerr << "Permutation " << i << ": " << outperm[i].ida << " <-> " << outperm[i].idb << endl;
	}

	rndstring.delCBitVector();
}

}
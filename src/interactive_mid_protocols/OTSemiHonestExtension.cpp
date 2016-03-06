#include "../../include/interactive_mid_protocols/OTSemiHonestExtension.hpp"

/***********************************/
/*   OTSemiHonestExtensionSender   */
/***********************************/

const char * OTSemiHonestExtensionBase::m_nSeed = "437398417012387813714564100";

OTSemiHonestExtensionSender::OTSemiHonestExtensionSender(SocketPartyData party, int koblitzOrZpSize, int numOfThreads) {
	//use ECC koblitz
	if (koblitzOrZpSize == 163 || koblitzOrZpSize == 233 || koblitzOrZpSize == 283) {

		m_bUseECC = true;
		//The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
		m_nSecParam = koblitzOrZpSize;
	}
	//use Zp
	else if (koblitzOrZpSize == 1024 || koblitzOrZpSize == 2048 || koblitzOrZpSize == 3072) {
		m_bUseECC = false;
		//The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
		m_nSecParam = koblitzOrZpSize;
	}
	senderPtr = InitOTSender(party.getIpAddress().to_string().c_str(), 
		party.getPort(), numOfThreads, true);
}
bool OTSemiHonestExtensionSender::Listen()
{
	if (!m_vSockets[0].Socket())
	{
		goto listen_failure;
	}
	if (!m_vSockets[0].Bind(m_nPort, m_nAddr))
		goto listen_failure;
	if (!m_vSockets[0].Listen())
		goto listen_failure;

	for (int i = 0; i<m_nNumOTThreads; i++) //twice the actual number, due to double sockets for OT
	{
		cout << "Waiting for receiver to connect on port: " << m_nPort << endl;
		CSocket sock;
		//cerr << "New round! " << endl;
		if (!m_vSockets[0].Accept(sock))
		{
			cerr << "Error in accept" << endl;
			goto listen_failure;
		}
		cout << "Receiver connected" << endl;
		UINT threadID;
		sock.Receive(&threadID, sizeof(int));
		if (threadID >= m_nNumOTThreads)
		{
			sock.Close();
			i--;
			continue;
		}
		// locate the socket appropriately
		m_vSockets[threadID].AttachFrom(sock);
		sock.Detach();
	}
	return true;

listen_failure:
	cerr << "Listen failed" << endl;
	return false;
}

bool OTSemiHonestExtensionSender::PrecomputeNaorPinkasSender()
{
	int nSndVals = 2;
	BYTE* pBuf = new BYTE[NUM_EXECS_NAOR_PINKAS * SHA1_BYTES];
	int log_nVals = (int)ceil(log((double)nSndVals) / log(2.0)), cnt = 0;
	U.Create(NUM_EXECS_NAOR_PINKAS*log_nVals, m_aSeed, cnt);
	bot->Receiver(nSndVals, NUM_EXECS_NAOR_PINKAS, U, m_vSockets[0], pBuf);
	//Key expansion
	BYTE* pBufIdx = pBuf;
	for (int i = 0; i<NUM_EXECS_NAOR_PINKAS; i++) //80 HF calls for the Naor Pinkas protocol
	{
		memcpy(vKeySeeds + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
		pBufIdx += SHA1_BYTES;
	}
	delete[] pBuf;
	return true;
}

OTExtensionSender* OTSemiHonestExtensionSender::InitOTSender(const char* address, int port, int numOfThreads, bool b_print)
{
	int nSndVals = 2;
	m_nPort = (USHORT)port;
	m_nAddr = address;
	vKeySeeds = (BYTE*)malloc(AES_KEY_BYTES*NUM_EXECS_NAOR_PINKAS);
	// initialize values
	Init(numOfThreads);
	// server listen
	Listen();
	auto start = scapi_now();
	PrecomputeNaorPinkasSender();
	auto otes = new OTExtensionSender(nSndVals, m_vSockets.data(), U, vKeySeeds);
	if (b_print)
		print_elapsed_ms(start, "PrecomputeNaorPinkasSender and OTExtensionSender init");
	return otes;
}

OTBatchSOutput* OTSemiHonestExtensionSender::transfer(OTBatchSInput * input) {
	int numOfOts;
	
	if (input->getType() == OTBatchSInputTypes::OTExtensionGeneralSInput ){ // in case the given input is general input.
		// retrieve the values from the input object.
		byte* x0 = ((OTExtensionGeneralSInput *)input)->getX0Arr();
		byte* x1 = ((OTExtensionGeneralSInput *)input)->getX1Arr();
		numOfOts = ((OTExtensionGeneralSInput *)input)->getNumOfOts();
		int x0Size = ((OTExtensionGeneralSInput *)input)->getX0ArrSize();
		runOtAsSender(x0, x1, NULL, numOfOts, x0Size / numOfOts * 8, "general");
		// This version has no output. Return null.
		return NULL;
	}
	//else if (OTExtensionCorrelatedSInput* general_input =
	//	dynamic_cast<OTExtensionCorrelatedSInput*>(input) {//In case the given input is correlated input.

	//	byte[] delta = ((OTExtensionCorrelatedSInput)input).getDelta();

	//	// Prepare empty x0 and x1 for the output.
	//	byte[] x0 = new byte[delta.length];
	//	byte[] x1 = new byte[delta.length];

	//	numOfOts = ((OTExtensionCorrelatedSInput)input).getNumOfOts();

	//	//Call the native function. It will fill x0 and x1.
	//	runOtAsSender(senderPtr, x0, x1, delta, numOfOts, delta.length / numOfOts * 8, "correlated");

	//	//Return output contains x0, x1.
	//	return new OTExtensionSOutput(x0, x1);

	//	//In case the given input is random input.
	//}
	//else if (input instanceof OTExtensionRandomSInput) {

	//	numOfOts = ((OTExtensionRandomSInput)input).getNumOfOts();
	//	int bitLength = ((OTExtensionRandomSInput)input).getBitLength();

	//	//Prepare empty x0 and x1 for the output.
	//	byte[] x0 = new byte[numOfOts * bitLength / 8];
	//	byte[] x1 = new byte[numOfOts * bitLength / 8];

	//	//Call the native function. It will fill x0 and x1.
	//	runOtAsSender(senderPtr, x0, x1, null, numOfOts, bitLength, "random");

	//	//Return output contains x0, x1.
	//	return new OTExtensionSOutput(x0, x1);
	//}
	else //If input is not instance of the above inputs, throw Exception.
		throw invalid_argument("input should be an instance of OTExtensionGeneralSInput or OTExtensionCorrelatedSInput or OTExtensionRandomSInput.");
}
void OTSemiHonestExtensionSender::runOtAsSender(byte *x1, byte * x2, byte * deltaArr, int numOfOts, int bitLength, string version) {
	//The masking function with which the values that are sent in the last communication step are processed
	//Choose OT extension version: G_OT, C_OT or R_OT
	BYTE ver;
	// supports all of the SHA hashes. Get the name of the required hash and instanciate that hash.
	if (version=="general")
		ver = G_OT;
	else if (version=="correlated")
		ver = C_OT;
	else if(version=="random")
		ver = R_OT;

	CBitVector delta, X1, X2;
	// create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values
	X1.Create(numOfOts, bitLength);
	X2.Create(numOfOts, bitLength);
	if (ver == G_OT) {
		//copy the values given from java
		for (int i = 0; i < numOfOts*bitLength / 8; i++)
		{
			X1.SetByte(i, x1[i]);
			X2.SetByte(i, x2[i]);
		}
	}
	else if (ver == C_OT) {
		m_fMaskFct = new XORMasking(bitLength);
		delta.Create(numOfOts, bitLength);
		//set the delta values given from java
		for (int i = 0; i < numOfOts*bitLength / 8; i++)
		{
			delta.SetByte(i, deltaArr[i]);
		}
		//creates delta as an array with "numOTs" entries of "bitlength" bit-values and fills delta with random values
		//delta.Create(numOfOts, bitLength, m_aSeed, m_nCounter);
	}
	//else if(ver==R_OT){} no need to set any values. There is no input for x0 and x1 and no input for delta
	//run the ot extension as the sender
	ObliviouslySend(senderPtr, X1, X2, numOfOts, bitLength, ver, delta);

	if (ver != G_OT) {//we need to copy x0 and x1 
		//get the values from the ot and copy them to x1Arr, x2Arr wich later on will be copied to the java values x1 and x2
		for (int i = 0; i < numOfOts*bitLength / 8; i++)
		{
			//copy each byte result to out
			x1[i] = X1.GetByte(i);
			x2[i] = X2.GetByte(i);
		}
		if (ver == C_OT) {
			delete m_fMaskFct;
		}
	}

	//make sure to release the memory created in c++. The JVM will not release it automatically.
	X1.delCBitVector();
	X2.delCBitVector();
	delta.delCBitVector();
}

bool OTSemiHonestExtensionSender::ObliviouslySend(OTExtensionSender* sender, CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, byte version, CBitVector& delta)
{
	bool success = FALSE;
	int nSndVals = 2; //Perform 1-out-of-2 OT
	// Execute OT sender routine 	
	success = sender->send(numOTs, bitlength, X1, X2, delta, version, m_nNumOTThreads, m_fMaskFct);
	return success;
}

/***********************************/
/*   OTSemiHonestExtensionReceiver */
/***********************************/

bool OTSemiHonestExtensionBase::Init(int numOfThreads)
{
	// Random numbers
	SHA_CTX sha;
	OTEXT_HASH_INIT(&sha);
	OTEXT_HASH_UPDATE(&sha, (BYTE*)&m_nPID, sizeof(m_nPID));
	OTEXT_HASH_UPDATE(&sha, (BYTE*)OTSemiHonestExtensionBase::m_nSeed, sizeof(m_nSeed));
	OTEXT_HASH_FINAL(&sha, m_aSeed);
	m_nCounter = 0;
	//Number of threads that will be used in OT extension
	m_nNumOTThreads = numOfThreads;
	m_vSockets.resize(m_nNumOTThreads);
	bot = new NaorPinkas(m_nSecParam, m_aSeed, m_bUseECC);
	return true;
}

bool OTSemiHonestExtensionReceiver::Connect(){
	bool bFail = false;
	LONG lTO = CONNECT_TIMEO_MILISEC;
	cout << "connecting to addr: " << m_nAddr << " port: " << m_nPort << endl;
	for (int k = m_nNumOTThreads - 1; k >= 0; k--)
	{
		for (int i = 0; i<RETRY_CONNECT; i++)
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
				if (k == 0)
					return TRUE;
				else
					break;
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
	return false;
}

bool OTSemiHonestExtensionReceiver::PrecomputeNaorPinkasReceiver()
{
	int nSndVals = 2;
	// Execute NP receiver routine and obtain the key 
	BYTE* pBuf = new BYTE[SHA1_BYTES * NUM_EXECS_NAOR_PINKAS * nSndVals];
	//=================================================	
	// N-P sender: send: C0 (=g^r), C1, C2, C3 
	bot->Sender(nSndVals, NUM_EXECS_NAOR_PINKAS, m_vSockets[0], pBuf);
	//Key expansion
	BYTE* pBufIdx = pBuf;
	for (int i = 0; i<NUM_EXECS_NAOR_PINKAS * nSndVals; i++)
	{
		memcpy(vKeySeedMtx + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
		pBufIdx += SHA1_BYTES;
	}
	delete[] pBuf;
	return true;
}

OTSemiHonestExtensionReceiver::OTSemiHonestExtensionReceiver(SocketPartyData party, int koblitzOrZpSize, int numOfThreads) {
	//use ECC koblitz
	if (koblitzOrZpSize == 163 || koblitzOrZpSize == 233 || koblitzOrZpSize == 283) {
		m_bUseECC = true;
		//The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
		m_nSecParam = koblitzOrZpSize;
	}
	//use Zp
	else if (koblitzOrZpSize == 1024 || koblitzOrZpSize == 2048 || koblitzOrZpSize == 3072) {
		m_bUseECC = false;
		//The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
		m_nSecParam = koblitzOrZpSize;
	}
	int nSndVals = 2;
	m_nPort = (USHORT)party.getPort();
	const std::string& tmp = party.getIpAddress().to_string();
	m_nAddr = tmp.c_str();
	vKeySeedMtx = (byte*)malloc(AES_KEY_BYTES*NUM_EXECS_NAOR_PINKAS * nSndVals);
	
	// initialize values
	Init(numOfThreads);

	// client connect
	Connect();
	PrecomputeNaorPinkasReceiver();
	receiverPtr = new OTExtensionReceiver(nSndVals, m_vSockets.data(), vKeySeedMtx, m_aSeed);
}

OTBatchROutput* OTSemiHonestExtensionReceiver::transfer(OTBatchRInput* input) {
	// we set the version to be the general case, if a different call was made we will change it later to the relevant version.
	string version = "general";
	
	if (input->getType() != OTBatchRInputTypes::OTExtensionGeneralRInput)
		throw invalid_argument("input should be instance of OTExtensionGeneralRInput");

	////If the user gave correlated input, change the version of the OT to correlated.
	//if (input instanceof OTExtensionCorrelatedRInput) {
	//	version = "correlated";
	//}

	////If the user gave random input, change the version of the OT to random.
	//if (input instanceof OTExtensionRandomRInput) {
	//	version = "random";
	//}

	byte* sigmaArr = ((OTExtensionRInput *)input)->getSigmaArr();
	int numOfOts = ((OTExtensionRInput *)input)->getSigmaArrSize();
	int elementSize = ((OTExtensionRInput *)input)->getElementSize();

	int outbytesLength = numOfOts*elementSize / 8;
	byte* outputBytes = new byte[outbytesLength];
	
	// run the protocol using the native code in the dll.
	runOtAsReceiver(sigmaArr, numOfOts, elementSize, outputBytes, version);
	return new OTOnByteArrayROutput(outputBytes, outbytesLength);
}

void OTSemiHonestExtensionReceiver::runOtAsReceiver(byte* sigma, int numOfOts, int bitLength, byte* output, std::string version) {
	BYTE ver;
	//supports all of the SHA hashes. Get the name of the required hash and instanciate that hash.
	if (version=="general")
		ver = G_OT;
	if (version=="correlated") {
		ver = C_OT;
		m_fMaskFct = new XORMasking(bitLength);
	}
	if (version=="random") 
		ver = R_OT;

	CBitVector choices, response;
	choices.Create(numOfOts);

	// pre-generate the respose vector for the results
	response.Create(numOfOts, bitLength);

	// copy the sigma values received from java
	for (int i = 0; i<numOfOts; i++) {
		choices.SetBit((i / 8) * 8 + 7 - (i % 8), sigma[i]);
		//choices.SetBit(i, sigmaArr[i]);
	}

	//run the ot extension as the receiver
	ObliviouslyReceive(choices, response, numOfOts, bitLength, ver);

	//prepare the out array
	for (int i = 0; i < numOfOts*bitLength / 8; i++)
		//copy each byte result to out
		output[i] = response.GetByte(i);

	// free the pointer of choises and reponse
	choices.delCBitVector();
	response.delCBitVector();
	if (ver == C_OT) 
		delete m_fMaskFct;
}

bool OTSemiHonestExtensionReceiver::ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version) {
	bool success = false;
	// Execute OT receiver routine 	

	success = receiverPtr->receive(numOTs, bitlength, choices, ret, version, m_nNumOTThreads, m_fMaskFct);
	return success;
}
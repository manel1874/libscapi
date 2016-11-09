/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


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
		semihonestot::CSocket sock;
		//cerr << "New round! " << endl;
		if (!m_vSockets[0].Accept(sock))
		{
			cerr << "Error in accept" << endl;
			goto listen_failure;
		}
		cout << "Receiver connected" << endl;
		semihonestot::UINT threadID;
		sock.Receive(&threadID, sizeof(int));
		if ((int) threadID >= m_nNumOTThreads)
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
	semihonestot::BYTE* pBuf = new semihonestot::BYTE[NUM_EXECS_NAOR_PINKAS * SHA1_BYTES];
	int log_nVals = (int)ceil(log((double)nSndVals) / log(2.0)), cnt = 0;
	U.Create(NUM_EXECS_NAOR_PINKAS*log_nVals, m_aSeed, cnt);
	bot->Receiver(nSndVals, NUM_EXECS_NAOR_PINKAS, U, m_vSockets[0], pBuf);
	//Key expansion
	semihonestot::BYTE* pBufIdx = pBuf;
	for (int i = 0; i<NUM_EXECS_NAOR_PINKAS; i++) //80 HF calls for the Naor Pinkas protocol
	{
		memcpy(vKeySeeds + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
		pBufIdx += SHA1_BYTES;
	}
	delete[] pBuf;
	return true;
}

semihonestot::OTExtensionSender* OTSemiHonestExtensionSender::InitOTSender(const char* address, int port, int numOfThreads, bool b_print)
{
	int nSndVals = 2;
	m_nPort = (semihonestot::USHORT)port;
	m_nAddr = address;
	vKeySeeds = new semihonestot::BYTE[AES_KEY_BYTES*NUM_EXECS_NAOR_PINKAS];
	// initialize values
	Init(numOfThreads);
	// server listen
	Listen();
	auto start = scapi_now();
	PrecomputeNaorPinkasSender();
	auto otes = new semihonestot::OTExtensionSender(nSndVals, m_vSockets.data(), U, vKeySeeds);
	if (b_print)
		print_elapsed_ms(start, "PrecomputeNaorPinkasSender and OTExtensionSender init");
	return otes;
}

shared_ptr<OTBatchSOutput> OTSemiHonestExtensionSender::transfer(OTBatchSInput * input) {
	int numOfOts;
	// in case the given input is general input.
	if (input->getType() == OTBatchSInputTypes::OTExtensionGeneralSInput ){ 
		// retrieve the values from the input object.
		auto x0 = ((OTExtensionGeneralSInput *)input)->getX0Arr();
		auto x1 = ((OTExtensionGeneralSInput *)input)->getX1Arr();
		numOfOts = ((OTExtensionGeneralSInput *)input)->getNumOfOts();
		auto x0Size = ((OTExtensionGeneralSInput *)input)->getX0ArrSize();
		vector<byte> empty;
		runOtAsSender(x0, x1, empty, numOfOts, x0Size / numOfOts * 8, "general");
		// This version has no output. Return null.
		return NULL;
	}
	//In case the given input is correlated input.
	else if (input->getType() == OTBatchSInputTypes::OTExtensionCorrelatedSInput) {

		auto delta = ((OTExtensionCorrelatedSInput *)input)->getDeltaArr();

		// Prepare empty x0 and x1 for the output.
		vector<byte> x0(delta.size());
		vector<byte> x1(delta.size());

		numOfOts = ((OTExtensionCorrelatedSInput *)input)->getNumOfOts();

		//Call the native function. It will fill x0 and x1.
		runOtAsSender(x0, x1, delta, numOfOts, delta.size() / numOfOts * 8, "correlated");

		//Return output contains x0, x1.
		return make_shared<OTExtensionCorrelatedSOutput>(x0, x1);
	
	}
	//In case the given input is random input.
	else if (input->getType() == OTBatchSInputTypes::OTExtensionRandomizedSInput) {

		numOfOts = ((OTExtensionRandomizedSInput *)input)->getNumOfOts();
		int bitLength = ((OTExtensionRandomizedSInput *)input)->getBitLength();

		//Prepare empty x0 and x1 for the output.
		vector<byte> x0(numOfOts * bitLength / 8);
		vector<byte> x1(numOfOts * bitLength / 8);

		//Call the native function. It will fill x0 and x1.
		vector<byte> empty;
		runOtAsSender(x0, x1, empty, numOfOts, bitLength, "random");

		//Return output contains x0, x1.
		return make_shared<OTExtensionRandomizedSOutput>(x0, x1);
	}
	else //If input is not instance of the above inputs, throw Exception.
		throw invalid_argument("input should be an instance of OTExtensionGeneralSInput or OTExtensionCorrelatedSInput or OTExtensionRandomizedSInput.");
}
void OTSemiHonestExtensionSender::runOtAsSender(vector<byte> & x1, vector<byte> & x2, const vector<byte> & deltaArr, int numOfOts, int bitLength, string version) {
	//The masking function with which the values that are sent in the last communication step are processed
	//Choose OT extension version: G_OT, C_OT or R_OT
	semihonestot::BYTE ver=0;
	// supports all of the SHA hashes. Get the name of the required hash and instanciate that hash.
	if (version=="general")
		ver = semihonestot::G_OT;
	else if (version=="correlated")
		ver = semihonestot::C_OT;
	else if(version=="random")
		ver = semihonestot::R_OT;
	semihonestot::CBitVector delta, X1, X2;
	// create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values
	X1.Create(numOfOts, bitLength);
	X2.Create(numOfOts, bitLength);
	if (ver == semihonestot::G_OT) {

		memcpy(X1.GetArr(), x1.data(), numOfOts*bitLength / 8);
		memcpy(X2.GetArr(), x2.data(), numOfOts*bitLength / 8);
		
	}
	else if (ver == semihonestot::C_OT) {
		m_fMaskFct = new semihonestot::XORMasking(bitLength);
		delta.Create(numOfOts, bitLength);

		//set the delta values given from java
		memcpy(delta.GetArr(), deltaArr.data(), numOfOts*bitLength / 8);
	}
	//run the ot extension as the sender
	
	ObliviouslySend(senderPtr, X1, X2, numOfOts, bitLength, ver, delta);
	
	if (ver != semihonestot::G_OT) {//we need to copy x0 and x1 
		//get the values from the ot and copy them to x1Arr, x2Arr wich later on will be copied to the java values x1 and x2
		memcpy(x1.data(), X1.GetArr(), numOfOts*bitLength / 8);
		memcpy(x2.data(), X2.GetArr(), numOfOts*bitLength / 8);
		
		if (ver == semihonestot::C_OT) {
			delete m_fMaskFct;
		}
	}

	//make sure to release the memory created in c++. The JVM will not release it automatically.
	X1.delCBitVector();
	X2.delCBitVector();
	delta.delCBitVector();
}

bool OTSemiHonestExtensionSender::ObliviouslySend(semihonestot::OTExtensionSender* sender, semihonestot::CBitVector& X1, semihonestot::CBitVector& X2, int numOTs, int bitlength, byte version, semihonestot::CBitVector& delta)
{
	bool success = FALSE;
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
	OTEXT_HASH_UPDATE(&sha, (semihonestot::BYTE*)&m_nPID, sizeof(m_nPID));
	OTEXT_HASH_UPDATE(&sha, (semihonestot::BYTE*)OTSemiHonestExtensionBase::m_nSeed, sizeof(m_nSeed));
	OTEXT_HASH_FINAL(&sha, m_aSeed);
	m_nCounter = 0;
	//Number of threads that will be used in OT extension
	m_nNumOTThreads = numOfThreads;
	m_vSockets.resize(m_nNumOTThreads);
	bot = new semihonestot::NaorPinkas(m_nSecParam, m_aSeed, m_bUseECC);
	return true;
}

bool OTSemiHonestExtensionReceiver::Connect(){
	semihonestot::LONG lTO = CONNECT_TIMEO_MILISEC;
	//cout << "connecting to addr: " << m_nAddr << " port: " << m_nPort << endl;
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
	semihonestot::BYTE* pBuf = new semihonestot::BYTE[SHA1_BYTES * NUM_EXECS_NAOR_PINKAS * nSndVals];
	//=================================================	
	// N-P sender: send: C0 (=g^r), C1, C2, C3 
	bot->Sender(nSndVals, NUM_EXECS_NAOR_PINKAS, m_vSockets[0], pBuf);
	//Key expansion
	semihonestot::BYTE* pBufIdx = pBuf;
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
	m_nPort = (semihonestot::USHORT)party.getPort();
	const std::string& tmp = party.getIpAddress().to_string();
	m_nAddr = tmp.c_str();
	vKeySeedMtx = (byte*)malloc(AES_KEY_BYTES*NUM_EXECS_NAOR_PINKAS * nSndVals);
	
	// initialize values
	Init(numOfThreads);

	// client connect
	Connect();
	PrecomputeNaorPinkasReceiver();
	receiverPtr = new semihonestot::OTExtensionReceiver(nSndVals, m_vSockets.data(), vKeySeedMtx, m_aSeed);
}

shared_ptr<OTBatchROutput> OTSemiHonestExtensionReceiver::transfer(OTBatchRInput* input) {
	// we set the version to be the general case, if a different call was made we will change it later to the relevant version.
	string version = "general";
	
	auto in = dynamic_cast<OTExtensionRInput*>(input);
	if (input == nullptr)
		throw invalid_argument("input should be instance of OTExtensionRInput");

	//If the user gave correlated input, change the version of the OT to correlated.
	auto correlatedIn = dynamic_cast<OTExtensionCorrelatedRInput*>(input);
	if (correlatedIn != nullptr) {
		version = "correlated";
	}

	//If the user gave random input, change the version of the OT to random.
	auto randomizedIn = dynamic_cast<OTExtensionRandomizedRInput*>(input);
	if (randomizedIn != nullptr) {
		version = "random";
	}

	auto sigmaArr = ((OTExtensionRInput *)input)->getSigmaArr();
	int numOfOts = ((OTExtensionRInput *)input)->getSigmaArrSize();
	int elementSize = ((OTExtensionRInput *)input)->getElementSize();

	// run the protocol using the native code in the dll.
	vector<byte> output = runOtAsReceiver(sigmaArr, numOfOts, elementSize, version);
	return make_shared<OTOnByteArrayROutput>(output);
	
}

vector<byte> OTSemiHonestExtensionReceiver::runOtAsReceiver(vector<byte> sigma, int numOfOts, int bitLength, std::string version) {
	semihonestot::BYTE ver;
	//supports all of the SHA hashes. Get the name of the required hash and instanciate that hash.
	if (version=="general")
		ver = semihonestot::G_OT;
	if (version=="correlated") {
		ver = semihonestot::C_OT;
		m_fMaskFct = new semihonestot::XORMasking(bitLength);
	}
	if (version=="random") 
		ver = semihonestot::R_OT;

	semihonestot::CBitVector choices, response;
	choices.Create(numOfOts);

	// pre-generate the respose vector for the results
	response.Create(numOfOts, bitLength);

	// copy the received sigma values
	for (int i = 0; i<numOfOts; i++) {
		choices.SetBit((i / 8) * 8 + 7 - (i % 8), sigma.at(i));
	}

	//run the ot extension as the receiver
	ObliviouslyReceive(choices, response, numOfOts, bitLength, ver);
	
	vector<byte> output(numOfOts*bitLength / 8);
	memcpy(output.data(), response.GetArr(), numOfOts*bitLength / 8);
	
	// free the pointer of choises and reponse
	choices.delCBitVector();
	response.delCBitVector();
	if (ver == semihonestot::C_OT)
		delete m_fMaskFct;

	return output;
}

bool OTSemiHonestExtensionReceiver::ObliviouslyReceive(semihonestot::CBitVector& choices, semihonestot::CBitVector& ret, int numOTs, int bitlength, semihonestot::BYTE version) {
	bool success = false;
	// Execute OT receiver routine 	

	success = receiverPtr->receive(numOTs, bitlength, choices, ret, version, m_nNumOTThreads, m_fMaskFct);
	return success;
}

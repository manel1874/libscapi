#pragma once

#include "../infra/Common.hpp"
#include "../CryptoInfra//SecurityLevel.hpp"
#include "../comm/Comm.hpp"
#include "OTBatch.hpp"

#include <OTExtension/util/typedefs.h>
#include <OTExtension/util/socket.h>
#include <OTExtension/ot/naor-pinkas.h>
#include <OTExtension/ot/asharov-lindell.h>
#include <OTExtension/ot/ot-extension.h>
#include <OTExtension/util/cbitvector.h>
#include <OTExtension/ot/xormasking.h>
#include <vector>
#include <time.h>

#include <limits.h>
#include <iomanip>
#include <string>

class OTSemiHonestExtensionBase : public SemiHonest {
protected:
	static const char* m_nSeed;
	semihonestot::USHORT m_nPort = 7766;
	const char* m_nAddr;// = "localhost";
	// Naor-Pinkas OT
	semihonestot::BaseOT* bot;
	// Network Communication
	vector<semihonestot::CSocket> m_vSockets;
	byte *vKeySeedMtx;
	int m_nCounter;
	int m_nNumOTThreads;
	int m_nPID; // thread id
	int m_nSecParam;
	bool m_bUseECC;
	semihonestot::MaskingFunction* m_fMaskFct;
	// SHA PRG
	semihonestot::BYTE m_aSeed[SHA1_BYTES];
	bool Init(int numOfThreads);
};

/*
* The native code that runs the OT extension as the receiver.
* @param sigma An array holding the input of the receiver, that is, the 0 and 1 choices for each OT.
* @param numOfOts The number or OTs that the protocol runs.
* @param bitLength The length of each item in the OT. The size of each x0, x1 which must be the same for all x0, x1.
* @param output The output of all the OTs. This is provided as a one dimensional array that gets all the data serially one after the other. The
* 				 array is given empty and the native code fills it with the result of the multiple OT results.
* @param version The particular OT type to run.
*/
//void runOtAsReceiver(byte* sigma, int numOfOts, int bitLength, byte* output, std::string version);

/**
* A concrete class for Semi-Honest OT extension sender. <P>
*
* The Semi-Honest OT extension implemented is a SCAPI wrapper of the native implementation by Michael Zohner from the paper: <p>
* "G. Asharov, Y. Lindell, T. Schneier and M. Zohner. More Efficient Oblivious Transfer and Extensions for Faster Secure Computation. ACM CCS 2013." <p>
* See http://eprint.iacr.org/2013/552.pdf for more information.
*
* The base OT is done once in the construction time. After that, the transfer function will be always optimized and fast, no matter how much OT's there are.
*
* There are three versions of OT extension: General, Correlated and Random. The difference between them is the way of getting the inputs: <p>
* In general OT extension both x0 and x1 are given by the user.<p>
* In Correlated OT extension the user gives a delta array and x0, x1 arrays are chosen such that x0 = delta^x1.<p>
* In random OT extension both x0 and x1 are chosen randomly.<p>
* To allow the user decide which OT extension's version he wants, each option has a corresponding input class. <p>
* The particular OT extension version is executed according to the given input instance;
* For example, if the user gave as input an instance of OTExtensionRandomSInput than the random OT Extension will be execute.<p>
*
* NOTE: Unlike a regular implementation the connection is done via the native code and thus the channel provided in the transfer function is ignored.
*/
class OTSemiHonestExtensionSender : public OTSemiHonestExtensionBase, public OTBatchSender {
private:
	semihonestot::OTExtensionSender* senderPtr;
	int m_nBitLength;
	int m_nMod;
	semihonestot::CBitVector U;
	semihonestot::BYTE *vKeySeeds;
	double rndgentime;

	semihonestot::OTExtensionSender* InitOTSender(const char* address, int port, int numOfThreads, bool b_print = false);
	bool ObliviouslySend(semihonestot::OTExtensionSender* sender, semihonestot::CBitVector& X1, semihonestot::CBitVector& X2, int numOTs, int bitlength, byte version, semihonestot::CBitVector& delta);
	bool Listen();
	bool PrecomputeNaorPinkasSender();
	void runOtAsSender(vector<byte> x1, vector<byte> x2, vector<byte> deltaArr, int numOfOts, int bitLength, string version);
public:
	/**
	* A constructor that creates the native sender with communication abilities. It uses the ip address and port given in the party object.<p>
	* The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	* @param party An object that holds the ip address and port.
	* @param koblitzOrZpSize An integer that determines whether the OT extension uses Zp or ECC koblitz. The optional parameters are the following.
	* 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp.
	* @param numOfThreads
	*/
	OTSemiHonestExtensionSender(SocketPartyData party, int koblitzOrZpSize = 163, int numOfThreads = 1);
	
	/**
	* The overloaded function that runs the protocol.<p>
	* After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	* @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	* @param input The input for the sender specifying the version of the OT extension to run.
	* Every call to the transfer function can run a different OT extension version.
	*/
	shared_ptr<OTBatchSOutput> transfer(OTBatchSInput * input) override;
	/**
	* Deletes the native OT object.
	*/
	~OTSemiHonestExtensionSender() { delete senderPtr; };
};

/**
* A concrete class for Semi-Honest OT extension receiver. <P>
*
* The Semi-Honest OT extension implemented is a SCAPI wrapper of the native implementation by Michael Zohner from the paper: <p>
* "G. Asharov, Y. Lindell, T. Schneier and M. Zohner. More Efficient Oblivious Transfer and Extensions for Faster Secure Computation. ACM CCS 2013." <p>
* See http://eprint.iacr.org/2013/552.pdf for more information.
*
* The base OT is done once in the construction time. After that, the transfer function will be always optimized and fast, no matter how much OT's there are.<p>
*
* There are three versions of OT extension: General, Correlated and Random. The difference between them is the way of getting the inputs: <p>
* In general OT extension both x0 and x1 are given by the user.<p>
* In Correlated OT extension the user gives a delta array and x0, x1 arrays are chosen such that x0 = delta^x1.<p>
* In random OT extension both x0 and x1 are chosen randomly.<p>
* To allow the user decide which OT extension's version he wants, each option has a corresponding input class. <p>
* The particular OT extension version is executed according to the given input instance;
* For example, if the user gave as input an instance of OTExtensionRandomRInput than the random OT Extension will be execute.<p>
*
* NOTE: Unlike a regular implementation, the connection is done via the native code and thus the channel provided in the transfer function is ignored.
*/
class OTSemiHonestExtensionReceiver : public OTSemiHonestExtensionBase, public OTBatchReceiver {
public:
	/**
	* A constructor that creates the native receiver with communication abilities. <p>
	* It uses the ip address and port given in the party object.<p>
	* The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	* @param party An object that holds the ip address and port.
	* @param koblitzOrZpSize An integer that determines whether the OT extension uses Zp or ECC koblitz. The optional parameters are the following.
	* 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp.
	* @param numOfThreads
	*
	*/
	OTSemiHonestExtensionReceiver(SocketPartyData party, int koblitzOrZpSize = 163, int numOfThreads = 1);
	
	/**
	* The overloaded function that runs the protocol.<p>
	* After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	* @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	* @param input The input for the receiver specifying the version of the OT extension to run.
	* Every call to the transfer function can run a different OT extension version.
	*/
	shared_ptr<OTBatchROutput> transfer(OTBatchRInput * input) override;
	/**
	* Deletes the native OT object.
	*/
	~OTSemiHonestExtensionReceiver() { delete receiverPtr; };
private:
	semihonestot::OTExtensionReceiver * receiverPtr;
	bool Connect();
	bool PrecomputeNaorPinkasReceiver();
	bool ObliviouslyReceive(semihonestot::CBitVector& choices, semihonestot::CBitVector& ret, int numOTs, int bitlength, semihonestot::BYTE version);
	/*
	* The native code that runs the OT extension as the receiver.
	* @param sigma An array holding the input of the receiver, that is, the 0 and 1 choices for each OT.
	* @param numOfOts The number or OTs that the protocol runs.
	* @param bitLength The length of each item in the OT. The size of each x0, x1 which must be the same for all x0, x1.
	* @param output The output of all the OTs. This is provided as a one dimensional array that gets all the data serially one after the other. The
	* 				 array is given empty and the native code fills it with the result of the multiple OT results.
	* @param version The particular OT type to run.
	*/
	vector<byte> runOtAsReceiver(vector<byte> sigma, int numOfOts, int bitLength, std::string version);
};



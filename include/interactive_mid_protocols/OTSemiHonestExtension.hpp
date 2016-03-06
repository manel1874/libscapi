#pragma once

#include "../infra/Common.hpp"
#include "../primitives/SecurityLevel.hpp"
#include "../comm/TwoPartyComm.hpp"

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

/**
* Any protocol that is secure in the presence of semi-honest adversaries should implement this interface.
*/
class SemiHonest : ProtocolSecLevel {};

/**
* This interface is a marker interface for OT sender output, where there is an implementing class for each OT protocol that has an output.<p>
* Most OT senders output nothing. However in the batch scenario there may be cases where the protocol wishes to output x0 and x1 instead of inputting it.
* Every concrete protocol outputs different data. But all must return an implemented class of this interface or null.
*/
class OTBatchSOutput {};

enum class OTBatchSInputTypes { OTExtensionGeneralSInput };
/**
* Every Batch OT sender needs inputs during the protocol execution, but every concrete protocol needs
* different inputs.<p>
* This interface is a marker interface for OT Batch sender input, where there is an implementing class
* for each OT protocol.
*/
class OTBatchSInput {
public:
	virtual OTBatchSInputTypes getType() = 0;
};

/**
* A concrete class for OT extension input for the sender. <p>
* In the general OT extension scenario the sender gets x0 and x1 for each OT.
*/
class OTExtensionGeneralSInput : public OTBatchSInput {
private:
	byte* x0Arr;	// An array that holds all the x0 for all the senders serially. 
					// For optimization reasons, all the x0 inputs are held in one dimensional array one after the other 
					// rather than a two dimensional array. 
					// The size of each element can be calculated by x0ArrSize/numOfOts.
	byte* x1Arr;	// An array that holds all the x1 for all the senders serially. 
	int x0ArrSize;
	int x1ArrSize;
	int numOfOts;	// Number of OTs in the OT extension.

public:
	OTBatchSInputTypes getType() override { return OTBatchSInputTypes::OTExtensionGeneralSInput; };
	/**
	* Constructor that sets x0, x1 for each OT element and the number of OTs.
	* @param x1Arr holds all the x0 for all the senders serially.
	* @param x0Arr holds all the x1 for all the senders serially.
	* @param numOfOts Number of OTs in the OT extension.
	*/
	OTExtensionGeneralSInput(byte* x0Arr, int x0ArrSize, byte* x1Arr, int x1ArrSize, int numOfOts) {
		this->x0Arr = x0Arr;
		this->x0ArrSize = x0ArrSize;
		this->x1Arr = x1Arr;
		this->x1ArrSize = x1ArrSize;
		this->numOfOts = numOfOts;
	};
	/**
	* @return the array that holds all the x0 for all the senders serially.
	*/
	byte* getX0Arr() { return x0Arr; };
	/**
	* @return the array that holds all the x1 for all the senders serially.
	*/
	byte* getX1Arr() { return x1Arr; };
	/**
	* @return the number of OT elements.
	*/
	int getNumOfOts() { return numOfOts; };
	int getX0ArrSize() { return x0ArrSize; };
	int getX1ArrSize() { return x1ArrSize; };
};

/**
* General interface for Batch OT Sender.
* Every class that implements it is signed as Batch Oblivious Transfer sender.
*/
class OTBatchSender {

public:
	/**
	* The transfer stage of OT Batch protocol which can be called several times in parallel.<p>
	* The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
	* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.<p>
	* This way the parallel executions of the function will not block each other.<p>
	*/
	virtual OTBatchSOutput * transfer(OTBatchSInput * input) = 0;
};


class OTSemiHonestExtensionBase : public SemiHonest {
protected:
	static const char* m_nSeed;
	USHORT m_nPort = 7766;
	const char* m_nAddr;// = "localhost";
	// Naor-Pinkas OT
	BaseOT* bot;
	// Network Communication
	vector<CSocket> m_vSockets;
	byte *vKeySeedMtx;
	int m_nCounter;
	int m_nNumOTThreads;
	int m_nPID; // thread id
	int m_nSecParam;
	bool m_bUseECC;
	MaskingFunction* m_fMaskFct;
	// SHA PRG
	BYTE m_aSeed[SHA1_BYTES];
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
void runOtAsReceiver(byte* sigma, int numOfOts, int bitLength, byte* output, std::string version);

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
	OTExtensionSender* senderPtr;
	int m_nBitLength;
	int m_nMod;
	CBitVector U;
	BYTE *vKeySeeds;
	double rndgentime;

	OTExtensionSender* InitOTSender(const char* address, int port, int numOfThreads, bool b_print = false);
	bool ObliviouslySend(OTExtensionSender* sender, CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, byte version, CBitVector& delta);
	bool Listen();
	bool PrecomputeNaorPinkasSender();
	void runOtAsSender(byte *x1, byte * x2, byte * deltaArr, int numOfOts, int bitLength, string version);
public:
	/**
	* A constructor that creates the native sender with communication abilities. It uses the ip address and port given in the party object.<p>
	* The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	* @param party An object that holds the ip address and port.
	* @param koblitzOrZpSize An integer that determines whether the OT extension uses Zp or ECC koblitz. The optional parameters are the following.
	* 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp.
	* @param numOfThreads
	*/
	OTSemiHonestExtensionSender(SocketPartyData party, int koblitzOrZpSize, int numOfThreads);
	/**
	* Default constructor. Initializes the sender by passing the ip address and uses koblitz 163 as a default dlog group.<P>
	* The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	*/
	OTSemiHonestExtensionSender(SocketPartyData party);
	/**
	* The overloaded function that runs the protocol.<p>
	* After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	* @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	* @param input The input for the sender specifying the version of the OT extension to run.
	* Every call to the transfer function can run a different OT extension version.
	*/
	OTBatchSOutput * transfer(OTBatchSInput * input) override;
	/**
	* Deletes the native OT object.
	*/
	~OTSemiHonestExtensionSender();
};

/**
* Every Batch OT receiver outputs a result in the end of the protocol execution, but every concrete
* protocol output different data.<p>
* This interface is a marker interface for OT receiver output, where there is an implementing class
* for each OT protocol.
*/
class OTBatchROutput {};

enum class OTBatchRInputTypes { OTExtensionGeneralRInput };

/**
* Every Batch OT receiver needs inputs during the protocol execution, but every concrete protocol needs
* different inputs.<p>
* This interface is a marker interface for OT receiver input, where there is an implementing class
* for each OT protocol.
*/
class OTBatchRInput {
public:
	virtual OTBatchRInputTypes getType() = 0;
};

/**
* General interface for Batch OT Receiver. <p>
* Every class that implements it is signed as Batch Oblivious Transfer receiver.<p>
*/
class OTBatchReceiver {
	/**
	* The transfer stage of OT Batch protocol which can be called several times in parallel.<p>
	* The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
	* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.<p>
	* This way the parallel executions of the function will not block each other.<p>
	* @param channel each call should get a different one.
	* @param input The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	* @return OTBatchROutput, the output of the protocol.
	*/
public:
	virtual OTBatchROutput *transfer(OTBatchRInput * input) = 0;
};

/**
* An abstract OT receiver input.<P>
* All the concrete classes are the same and differ only in the name.
* The reason a class is created for each version is due to the fact that a respective class is created for the sender and we wish to be consistent.
* The name of the class determines the version of the OT extension we wish to run.
* In all OT extension scenarios the receiver gets i bits. Each byte holds a bit for each OT in the OT extension protocol.
*/
class OTExtensionRInput : public OTBatchRInput {
public:
	/**
	* Constructor that sets the sigma array and the number of OT elements.
	* @param sigmaArr An array of sigma for each OT.
	* @param elementSize The size of each element in the OT extension, in bits.
	*/
	OTExtensionRInput(byte* sigmaArr, int sigmeArrSize, int elementSize) {
		this->sigmaArr = sigmaArr;
		this->sigmeArrSize = sigmeArrSize;
		this->elementSize = elementSize;
	};
	byte* getSigmaArr() { return sigmaArr; };
	int getSigmaArrSize() { return sigmeArrSize; };
	int getElementSize() { return elementSize; };
	OTBatchRInputTypes getType() { return OTBatchRInputTypes::OTExtensionGeneralRInput; };
private:
	byte* sigmaArr; 		// Each byte holds a sigma bit for each OT in the OT extension protocol.
	int sigmeArrSize; // size of the arr
	int elementSize;	// The size of each element in the ot extension. All elements must be of the same size.
};

/**
* A concrete class for OT extension input for the receiver. <p>
* All the classes are the same and differ only in the name.
* The reason a class is created for each version is due to the fact that a respective class is created for the sender and we wish to be consistent.
* The name of the class determines the version of the OT extension we wish to run and in this case the general case.
*/
class OTExtensionGeneralRInput : public OTExtensionRInput {
public:
	/**
	* Constructor that sets the sigma array and the number of OT elements.
	* @param sigmaArr An array of sigma for each OT.
	* @param elementSize The size of each element in the OT extension, in bits.
	*/
	OTExtensionGeneralRInput(byte* sigmaArr, int arrSize, int elementSize) : OTExtensionRInput(sigmaArr, arrSize, elementSize) {};
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
	OTSemiHonestExtensionReceiver(SocketPartyData party, int koblitzOrZpSize, int numOfThreads);
	/**
	* Default constructor. Initializes the receiver by passing the ip address and uses koblitz 163 as a default dlog group. <P>
	* The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	* @param party An object that holds the ip address and port.
	*/
	OTSemiHonestExtensionReceiver(SocketPartyData party) : OTSemiHonestExtensionReceiver(party, 163, 1) {};
	/**
	* The overloaded function that runs the protocol.<p>
	* After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	* @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	* @param input The input for the receiver specifying the version of the OT extension to run.
	* Every call to the transfer function can run a different OT extension version.
	*/
	OTBatchROutput * transfer(OTBatchRInput * input) override;
	/**
	* Deletes the native OT object.
	*/
	~OTSemiHonestExtensionReceiver() { delete receiverPtr; };
private:
	OTExtensionReceiver * receiverPtr; 
	bool Connect();
	bool PrecomputeNaorPinkasReceiver();
	bool ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version);
	/*
	* The native code that runs the OT extension as the receiver.
	* @param sigma An array holding the input of the receiver, that is, the 0 and 1 choices for each OT.
	* @param numOfOts The number or OTs that the protocol runs.
	* @param bitLength The length of each item in the OT. The size of each x0, x1 which must be the same for all x0, x1.
	* @param output The output of all the OTs. This is provided as a one dimensional array that gets all the data serially one after the other. The
	* 				 array is given empty and the native code fills it with the result of the multiple OT results.
	* @param version The particular OT type to run.
	*/
	void runOtAsReceiver(byte* sigma, int numOfOts, int bitLength, byte* output, std::string version);
};

/**
* Every OT receiver outputs a result in the end of the protocol execution, but every concrete
* protocol output different data.<p>
* This interface is a marker interface for OT receiver output, where there is an implementing class
* for each OT protocol.
*/
class OTROutput {};

/**
* Concrete implementation of OT receiver (on byteArray) output.<p>
* In the byteArray scenario, the receiver outputs xSigma as a byte array.
* This output class also can be viewed as the output of batch OT when xSigma is a concatenation of all xSigma byte array of all OTs.
*/
class OTOnByteArrayROutput : public OTROutput, public OTBatchROutput {
public:
	OTOnByteArrayROutput(byte* xSigma, int length) { this->xSigma = xSigma; this->length = length; };
	byte* getXSigma() { return xSigma; };
	int getLength() { return length; };
private:
	byte* xSigma;
	int length;
};

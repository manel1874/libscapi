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


#pragma once

#include "../infra/Common.hpp"
#include "../cryptoInfra/SecurityLevel.hpp"
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

/**
* Abstract class that implement some common functionality for both the sender and the receiver of this OT extension implementation.
*/
class OTSemiHonestExtensionBase : public SemiHonest {
protected:
	static const char* m_nSeed;
	semihonestot::USHORT m_nPort = 7766;
	const char* m_nAddr;
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

	~OTSemiHonestExtensionBase() {
		delete bot;
	}
};

/**
* A concrete class for Semi-Honest OT extension sender. 
*
* The Semi-Honest OT extension implemented is a SCAPI wrapper of the Michael Zohner's implementation from the paper:
* "G. Asharov, Y. Lindell, T. Schneier and M. Zohner. More Efficient Oblivious Transfer and Extensions for Faster Secure Computation. ACM CCS 2013." 
* See http://eprint.iacr.org/2013/552.pdf for more information.
*
* The base OT is done once in the construction time. After that, the transfer function will be always optimized and fast, no matter how much OT's there are.
*
* There are three versions of OT extension: General, Correlated and Random. The difference between them is the way of getting the inputs:
* In general OT extension both x0 and x1 are given by the user.
* In Correlated OT extension the user gives a delta array and x0, x1 arrays are chosen such that x0 = delta^x1.
* In random OT extension both x0 and x1 are chosen randomly.
* To allow the user decide which OT extension's version he wants, each option has a corresponding input class. 
* The particular OT extension version is executed according to the given input instance;
* For example, if the user gave as input an instance of OTExtensionRandomSInput than the random OT Extension will be execute.
*
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
	void runOtAsSender(vector<byte> & x1, vector<byte> & x2, const vector<byte> & deltaArr, int numOfOts, int bitLength, string version);
public:
	/**
	* A constructor that creates the native sender with communication abilities. It uses the ip address and port given in the party object.
	* The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	* @param party An object that holds the ip address and port.
	* @param koblitzOrZpSize An integer that determines whether the OT extension uses Zp or ECC koblitz. The optional parameters are the following.
	* 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp.
	* @param numOfThreads
	*/
	OTSemiHonestExtensionSender(SocketPartyData party, int koblitzOrZpSize = 163, int numOfThreads = 1);
	
	/**
	* The overloaded function that runs the protocol.
	* After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	* @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	* @param input The input for the sender specifying the version of the OT extension to run.
	* Every call to the transfer function can run a different OT extension version.
	*/
	shared_ptr<OTBatchSOutput> transfer(OTBatchSInput * input) override;
	/**
	* Deletes the library's OT object.
	*/
	~OTSemiHonestExtensionSender() { 
		delete senderPtr;
		delete vKeySeeds;
	};
};

/**
* A concrete class for Semi-Honest OT extension receiver. 
*
* The Semi-Honest OT extension implemented is a SCAPI wrapper of the Michael Zohner's implementation from the paper: 
* "G. Asharov, Y. Lindell, T. Schneier and M. Zohner. More Efficient Oblivious Transfer and Extensions for Faster Secure Computation. ACM CCS 2013." 
* See http://eprint.iacr.org/2013/552.pdf for more information.
*
* The base OT is done once in the construction time. After that, the transfer function will be always optimized and fast, no matter how much OT's there are.
*
* There are three versions of OT extension: General, Correlated and Random. The difference between them is the way of getting the inputs: 
* In general OT extension both x0 and x1 are given by the user
* In Correlated OT extension the user gives a delta array and x0, x1 arrays are chosen such that x0 = delta^x1.
* In random OT extension both x0 and x1 are chosen randomly.
* To allow the user decide which OT extension's version he wants, each option has a corresponding input class. 
* The particular OT extension version is executed according to the given input instance;
* For example, if the user gave as input an instance of OTExtensionRandomRInput than the random OT Extension will be execute.

*/
class OTSemiHonestExtensionReceiver : public OTSemiHonestExtensionBase, public OTBatchReceiver {
public:
	/**
	* A constructor that creates the native receiver with communication abilities. 
	* It uses the ip address and port given in the party object.
	* The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	* @param party An object that holds the ip address and port.
	* @param koblitzOrZpSize An integer that determines whether the OT extension uses Zp or ECC koblitz. The optional parameters are the following.
	* 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp.
	* @param numOfThreads
	*
	*/
	OTSemiHonestExtensionReceiver(SocketPartyData party, int koblitzOrZpSize = 163, int numOfThreads = 1);
	
	/**
	* The overloaded function that runs the protocol.
	* After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	* @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	* @param input The input for the receiver specifying the version of the OT extension to run.
	* Every call to the transfer function can run a different OT extension version.
	*/
	shared_ptr<OTBatchROutput> transfer(OTBatchRInput * input) override;
	/**
	* Deletes the library's OT object.
	*/
	~OTSemiHonestExtensionReceiver() { delete receiverPtr; };
private:
	semihonestot::OTExtensionReceiver * receiverPtr;
	bool Connect();
	bool PrecomputeNaorPinkasReceiver();
	bool ObliviouslyReceive(semihonestot::CBitVector& choices, semihonestot::CBitVector& ret, int numOTs, int bitlength, semihonestot::BYTE version);
	/*
	* Runs the underlying OT extension receiver.
	* @param sigma An array holding the input of the receiver, that is, the 0 and 1 choices for each OT.
	* @param numOfOts The number or OTs that the protocol runs.
	* @param bitLength The length of each item in the OT. The size of each x0, x1 which must be the same for all x0, x1.
	* @param output The output of all the OTs. This is provided as a one dimensional array that gets all the data serially one after the other. The
	* 				 array is given empty and the native code fills it with the result of the multiple OT results.
	* @param version The particular OT type to run.
	*/
	vector<byte> runOtAsReceiver(vector<byte> sigma, int numOfOts, int bitLength, std::string version);
};



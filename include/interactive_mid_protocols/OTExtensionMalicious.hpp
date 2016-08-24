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
#include "../CryptoInfra/SecurityLevel.hpp"
#include "OTBatch.hpp"
#include "../comm/Comm.hpp"

#include <MaliciousOTExtension/util/typedefs.h>
#include <MaliciousOTExtension/util/socket.h>
#include <MaliciousOTExtension/util/cbitvector.h>
#include <MaliciousOTExtension/ot/ot-extension-malicious.h>
#include <MaliciousOTExtension/ot/xormasking.h>
#include <MaliciousOTExtension/ot/pvwddh.h>

class ConnectionManager;

class OTExtensionMaliciousBase : public Malicious {
protected:
	// handles the networking stuff
	ConnectionManager* m_connection_manager;

	// handles the malicious ot protocol 
	// (each party runs both a sender and a receiver since 
	// there are 2 ots running: the base ot and the extension ot).
	maliciousot::Mal_OTExtensionSender* m_sender;
	maliciousot::Mal_OTExtensionReceiver*  m_receiver;

	// Naor-Pinkas OT protocol
	maliciousot::BaseOT * m_baseot_handler;

	// settings of ot protocol
	int m_num_base_ots;
	int m_num_ots;
	int m_counter;
	int m_num_checks;
	maliciousot::SECLVL m_security_level;

	// seeds (SHA PRG)
	maliciousot::BYTE m_receiver_seed[SHA1_BYTES];
	maliciousot::BYTE m_sender_seed[AES_BYTES];

	// implementation details
	maliciousot::CBitVector U;
	maliciousot::BYTE *m_sender_key_seeds;
	maliciousot::BYTE *m_receiver_key_seeds_matrix;

	// logger stuff
	double logger_random_gentime;

	
	void init_seeds(int role);
public:
	static const char* m_initial_seed;
	OTExtensionMaliciousBase(int role, int num_base_ots, int num_ots);
	virtual ~OTExtensionMaliciousBase();

};
/**
* A concrete class for Malicious OT extension sender. <P>
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
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy, Asaf Cohen)
*
*/
class OTExtensionMaliciousSender  : public OTExtensionMaliciousBase, public OTBatchSender {
private:
	BOOL precompute_base_ots_sender();
	/*
	* runs the OT extension as the sender.
	* @param x0 An array that holds all the x0 values for each of the OT's serially (concatenated).
	* @param x1 An array that holds all the x1 values for each of the OT's serially (concatenated).
	* @param delta
	* @param numOfOts The number of OTs that the protocol runs (how many strings are inside x0?)
	* @param bitLength The length (in bits) of each item in the OT. can be derived from |x0|, |x1|, numOfOts
	* @param version the OT extension version the user wants to use.
	*/
	void runOtAsSender(vector<byte>& x0, vector<byte>& x1, vector<byte>& delta, int numOfOts, int bitLength, maliciousot::BYTE version);
	
public:
	/**
	* A constructor that creates the native sender with communication abilities. It uses the ip address and port given in the party object.<p>
	* The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	* THE SENDER ACTS AS THE SERVER!!!
	* @param party An object that holds the ip address and port.
	* @param koblitzOrZpSize An integer that determines whether the OT extension uses Zp or ECC koblitz. The optional parameters are the following.
	* 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp.
	* @param numOfThreads
	*/
	OTExtensionMaliciousSender(SocketPartyData bindAddress, int numOts, int numOfThreads = 1, int numBaseOts = 190);
	~OTExtensionMaliciousSender();
	/**
	* The overloaded function that runs the protocol.<p>
	* After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	* @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	* @param input The input for the sender specifying the version of the OT extension to run.
	* Every call to the transfer function can run a different OT extension version.
	*/
	shared_ptr<OTBatchSOutput> transfer(OTBatchSInput * input) override;
};

/**
* A concrete class for Malicious OT extension receiver. <P>
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
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy, Asaf Cohen)
*
*/
class OTExtensionMaliciousReceiver : public OTExtensionMaliciousBase, public OTBatchReceiver {

private:
	BOOL precompute_base_ots_receiver();
							  
	/*
	* The native code that runs the OT extension as the receiver.
	* @param receiverPtr The pointer initialized via the function initOtReceiver
	* @param sigma An array holding the input of the receiver, that is, the 0 and 1 choices for each OT.
	* @param numOfOts The number or OTs that the protocol runs.
	* @param bitLength The length of each item in the OT. The size of each x0, x1 which must be the same for all x0, x1.
	* @param output The output of all the OTs. This is provided as a one dimensional array that gets all the data serially one after the other. The
	* 				 array is given empty and the native code fills it with the result of the multiple OT results.
	* @param version The particular OT type to run.
	*/
	vector<byte> runOtAsReceiver(vector<byte>& sigma, int numOfOts, int bitLength, maliciousot::BYTE version);
	
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
	OTExtensionMaliciousReceiver(SocketPartyData serverAddress, int numOts, int numOfThreads = 1, int numBaseOts = 190);
	~OTExtensionMaliciousReceiver();
	/**
	* The overloaded function that runs the protocol.<p>
	* After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	* @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	* @param input The input for the receiver specifying the version of the OT extension to run.
	* Every call to the transfer function can run a different OT extension version.
	*/
	shared_ptr<OTBatchROutput> transfer(OTBatchRInput * input) override;
};





// abstract base class
class ConnectionManager {

public:
	static const char * DEFAULT_ADDRESS;
	static const maliciousot::USHORT DEFAULT_PORT = 7766;

	// ctors
	ConnectionManager(int role, int num_of_threads, SocketPartyData address);
	
	// dtor
	virtual ~ConnectionManager();

	void cleanup();
	inline maliciousot::CSocket * get_sockets_data() { return m_sockets.data(); };
	inline maliciousot::CSocket& get_socket(int i) { return m_sockets[i]; };
	inline int get_num_of_threads() { return m_num_of_threads; };
	virtual BOOL setup_connection() = 0;

protected:
	int m_num_of_threads;
	string m_address;
	maliciousot::USHORT m_port;
	int m_pid; // thread id - indicates the role: (0 for server, 1 for client)
	std::vector<maliciousot::CSocket> m_sockets;
};

// server class (used by sender)
class ConnectionManagerServer : public ConnectionManager {
public:
	ConnectionManagerServer(int role, int num_of_threads, SocketPartyData address);
	virtual BOOL setup_connection();
};

// client class (used by receiver)
class ConnectionManagerClient : public ConnectionManager {
public:
	ConnectionManagerClient(int role, int num_of_threads, SocketPartyData address);
	virtual BOOL setup_connection();
};




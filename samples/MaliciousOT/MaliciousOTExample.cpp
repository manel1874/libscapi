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


#include "../include/interactive_mid_protocols/OTExtensionMalicious.hpp"

void mainR() {
	// init phase
	int numOts = 1;
	srand(time(NULL));
	SocketPartyData senderParty(IpAdress::from_string("127.0.0.1"), 7766);
	OTExtensionMaliciousReceiver* receiver_interface = new OTExtensionMaliciousReceiver(senderParty, numOts); // total ots

	vector<byte> choices, response;
	
	//copy the sigma values received from java
	for (int i = 0; i<numOts; i++) {
		choices.push_back(1);
	}

	//run the ot extension as the receiver
	//OTBatchRInput * input = new OTExtensionGeneralRInput(choices, 128);
	//OTBatchRInput * input = new OTExtensionCorrelatedRInput(choices, 128);
	OTBatchRInput * input = new OTExtensionRandomizedRInput(choices, 128);
	auto output = receiver_interface->transfer(input);
	
	//prepare the out array
	auto arr = ((OTOnByteArrayROutput*)(output.get()))->getXSigma();
	for (size_t i = 0; i < arr.size(); i++) {
		cout << (int) arr.at(i) << " ";
	}
	cout << endl;

	delete receiver_interface;
}

void mainS() {
	// init phase
	int numOts = 1;
	int bitLength = 128;
	srand(time(NULL));
	SocketPartyData senderParty(IpAdress::from_string("127.0.0.1"), 7766);
	OTExtensionMaliciousSender * sender_interface = new OTExtensionMaliciousSender(senderParty, numOts); // total ots
	
	// run ot as sender phase
	vector<byte> delta, X1, X2;
	
	for (int i = 0; i < numOts * bitLength / 8; i++) {
		X1.push_back(0);
		X2.push_back(1);
	}

	//OTBatchSInput * input = new OTExtensionGeneralSInput(X1, X2, numOts);
	//OTBatchSInput * input = new OTExtensionCorrelatedSInput(X1, numOts);
	OTBatchSInput * input = new OTExtensionRandomizedSInput(bitLength, numOts);
	auto output = sender_interface->transfer(input); 
	
	cout << "x0 : " << endl;
	auto x0 = ((OTExtensionCorrelatedSOutput*)(output.get()))->getx0Arr();
	for (size_t i = 0; i < x0.size(); i++) {
		cout << (int)x0.at(i) << " ";
	}
	cout << endl;
	cout << "x1 : " << endl;
	auto x1 = ((OTExtensionCorrelatedSOutput*)(output.get()))->getx1Arr();
	for (size_t i = 0; i < x1.size(); i++) {
		cout << (int)x1.at(i) << " ";
	}
	cout << endl;

	
	delete sender_interface;
}


int mainOTMalicious(string party) {

	if (party == "1") {
		mainS();
	}
	else {
		mainR();
	}
	return 1;
}

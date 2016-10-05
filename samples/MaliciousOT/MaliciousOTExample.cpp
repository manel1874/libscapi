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
	int numOts = 128000;
	srand(time(NULL));
	SocketPartyData senderParty(IpAdress::from_string("127.0.0.1"), 7766);
	OTExtensionMaliciousReceiver* receiver_interface = new OTExtensionMaliciousReceiver(senderParty, numOts); // total ots

	cerr << "finished initOtReceiver." << endl;
	cerr << "Started runOtAsSender." << endl;

	//maliciousot::MaskingFunction * masking_function = new maliciousot::XORMasking(bitLength);

	vector<byte> choices, response;
	//choices.Create(numOts);

	//Pre-generate the response vector for the results
	//response.Create(numOts, bitLength);

	//copy the sigma values received from java
	for (int i = 0; i<numOts; i++) {
		//choices.push_back((byte)((i / 8) * 8 + 7 - (i % 8), rand() % 2));
		choices.push_back(1);
	}

	//run the ot extension as the receiver
	OTBatchRInput * input = new OTExtensionGeneralRInput(choices, 128);
	cerr << "started receiver_interface->obliviously_receive()" << endl;
	auto start = scapi_now();
	auto output = receiver_interface->transfer(input);
	print_elapsed_ms(start, "Transfer for general");
	cerr << "ended receiver_interface->obliviously_receive()" << endl;

	//prepare the out array
	cerr << "response bitvector:" << endl;
	auto arr = ((OTOnByteArrayROutput*)(output.get()))->getXSigma();
	for (size_t i = 0; i < arr.size(); i++) {
		cout << (int) arr.at(i) << " ";
	}
	cout << endl;

	//choices.delCBitVector();
	//response.delCBitVector();

	//delete masking_function;
	cerr << "ended runOtAsReceiver." << endl;
	delete receiver_interface;
}

void mainS() {
	// init phase
	int numOts = 128000;
	int bitLength = 128;
	srand(time(NULL));
	SocketPartyData senderParty(IpAdress::from_string("127.0.0.1"), 7766);
	OTExtensionMaliciousSender * sender_interface = new OTExtensionMaliciousSender(senderParty, numOts); // total ots
	cerr << "finished initOtSender." << endl;

	// run ot as sender phase
	vector<byte> delta, X1, X2;
	//maliciousot::MaskingFunction * masking_function = new maliciousot::XORMasking(bitLength);

	//Create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values
	//X1.Create(numOts, bitLength);
	//X2.Create(numOts, bitLength);
	for (int i = 0; i < numOts * bitLength / 8; i++) {
		//X1.push_back(rand() % 2);
		//X2.push_back(rand() % 2);
		X1.push_back(0);
		X2.push_back(1);
	}

	OTBatchSInput * input = new OTExtensionGeneralSInput(X1, X2, numOts);
	cerr << "started receiver_interface->obliviously_send()" << endl;
	auto start = scapi_now();
	sender_interface->transfer(input); //, delta);
	print_elapsed_ms(start, "Transfer for general");
	cerr << "ended receiver_interface->obliviously_send()" << endl;
	//X1.delCBitVector();
	//X2.delCBitVector();
	//delta.delCBitVector();

	cerr << "ended runOtAsSender." << endl;

	delete sender_interface;
}


int mainOTMalicious(string party) {

	cout << "argv[2] = " << party << endl;
	if (party == "1") {
		mainS();
	}
	else {
		mainR();
	}
	return 1;
}

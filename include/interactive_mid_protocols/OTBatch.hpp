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
#include "OT.hpp"
#include <emmintrin.h>
#ifndef _WIN32
#include <OTExtensionBristol/OT/BitMatrix.h>
#include <OTExtensionBristol/OT/BitVector.h>
#endif
/**
 * This interface is a marker interface for OT sender output, where there is an implementing class for each OT protocol that has an output.<p>
 * Most OT senders output nothing. However in the batch scenario there may be cases where the protocol wishes to output x0 and x1 instead of inputting it.
 * Every concrete protocol outputs different data. But all must return an implemented class of this interface or null.
 */
class OTBatchSOutput {
};


class OTExtensionRandomizedSOutput: public OTBatchSOutput {

protected:

	vector<byte> r0Arr;
	vector<byte> r1Arr;

public:

	/**
	 * @return the array that holds all the x0 for all the senders serially.
	 */
	vector<byte> getR0Arr() {
		return r0Arr;
	}
	;
	/**
	 * @return the array that holds all the x1 for all the senders serially.
	 */
	vector<byte> getR1Arr() {
		return r1Arr;
	}
};


#ifndef _WIN32
class OTExtensionBristolRandomizedSOutput: public OTExtensionRandomizedSOutput {

public:

	OTExtensionBristolRandomizedSOutput(const vector<BitMatrix>& senderOutputMatrices) {

		copy_byte_array_to_byte_vector((byte*)senderOutputMatrices[0].squares.data(), senderOutputMatrices[0].squares.size()*128*16, r0Arr, 0);
		copy_byte_array_to_byte_vector((byte*)senderOutputMatrices[1].squares.data(), senderOutputMatrices[1].squares.size()*128*16, r1Arr, 0);

	};

};

#endif

enum class OTBatchSInputTypes {
	OTExtensionGeneralSInput, OTExtensionRandomizedSInput
};

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
class OTExtensionGeneralSInput: public OTBatchSInput {
private:
	vector<byte> x0Arr; // An array that holds all the x0 for all the senders serially.
	// For optimization reasons, all the x0 inputs are held in one dimensional array one after the other
	// rather than a two dimensional array.
	// The size of each element can be calculated by x0ArrSize/numOfOts.
	vector<byte> x1Arr; // An array that holds all the x1 for all the senders serially.
	int numOfOts; // Number of OTs in the OT extension.

public:
	OTBatchSInputTypes getType()override {return OTBatchSInputTypes::OTExtensionGeneralSInput;};
	/**
	 * Constructor that sets x0, x1 for each OT element and the number of OTs.
	 * @param x1Arr holds all the x0 for all the senders serially.
	 * @param x0Arr holds all the x1 for all the senders serially.
	 * @param numOfOts Number of OTs in the OT extension.
	 */
	OTExtensionGeneralSInput(vector<byte> x0Arr, vector<byte> x1Arr,
			int numOfOts) {
		this->x0Arr = x0Arr;
		this->x1Arr = x1Arr;
		this->numOfOts = numOfOts;
	}
	;
	/**
	 * @return the array that holds all the x0 for all the senders serially.
	 */
	vector<byte> getX0Arr() {
		return x0Arr;
	}
	;
	/**
	 * @return the array that holds all the x1 for all the senders serially.
	 */
	vector<byte> getX1Arr() {
		return x1Arr;
	}
	;
	/**
	 * @return the number of OT elements.
	 */
	int getNumOfOts() {
		return numOfOts;
	}
	;
	int getX0ArrSize() {
		return x0Arr.size();
	}
	;
	int getX1ArrSize() {
		return x1Arr.size();
	}
	;
};


/**
 * A concrete class for randomized OT extension input for the sender. <p>
 * In the radomized OT extension scenario the sender gets has no x0 and x1 as input, rather this is an output from the protocol.
 */
class OTExtensionRandomizedSInput: public OTBatchSInput {
private:
	int numOfOts; // Number of OTs in the OT extension.

public:
	OTBatchSInputTypes getType() override {return OTBatchSInputTypes::OTExtensionRandomizedSInput;};
	/**
	 * Constructor that sets the number of OTs.
	 * @param x1Arr holds all the x0 for all the senders serially.
	 * @param x0Arr holds all the x1 for all the senders serially.
	 * @param numOfOts Number of OTs in the OT extension.
	 */
	OTExtensionRandomizedSInput(int numOfOts) :
		numOfOts(numOfOts) {
	}
	;
	int getNumOfOts() {
		return numOfOts;
	}
	;

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
	virtual shared_ptr<OTBatchSOutput> transfer(OTBatchSInput * input) = 0;
	virtual ~OTBatchSender(){};
};



enum class OTBatchRInputTypes {
	OTExtensionGeneralRInput, OTExtensionRandomizedRInput
};

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
 * An abstract OT receiver input.<P>
 * All the concrete classes are the same and differ only in the name.
 * The reason a class is created for each version is due to the fact that a respective class is created for the sender and we wish to be consistent.
 * The name of the class determines the version of the OT extension we wish to run.
 * In all OT extension scenarios the receiver gets i bits. Each byte holds a bit for each OT in the OT extension protocol.
 */
class OTExtensionRInput: public OTBatchRInput {
public:
	/**
	 * Constructor that sets the sigma array and the number of OT elements.
	 * @param sigmaArr An array of sigma for each OT.
	 * @param elementSize The size of each element in the OT extension, in bits.
	 */
	OTExtensionRInput(vector<byte> sigmaArr, int elementSize) {
		this->sigmaArr = sigmaArr;
		this->elementSize = elementSize;
	}
	;
	vector<byte> getSigmaArr() {
		return sigmaArr;
	}
	;
	int getSigmaArrSize() {
		return sigmaArr.size();
	}
	;
	int getElementSize() {
		return elementSize;
	}
	;

private:
	vector<byte> sigmaArr; // Each byte holds a sigma bit for each OT in the OT extension protocol.
	int elementSize; // The size of each element in the ot extension. All elements must be of the same size.
};

/**
 * A concrete class for OT extension input for the receiver. <p>
 * All the classes are the same and differ only in the name.
 * The reason a class is created for each version is due to the fact that a respective class is created for the sender and we wish to be consistent.
 * The name of the class determines the version of the OT extension we wish to run and in this case the general case.
 */
class OTExtensionGeneralRInput: public OTExtensionRInput {
public:
	/**
	 * Constructor that sets the sigma array and the number of OT elements.
	 * @param sigmaArr An array of sigma for each OT.
	 * @param elementSize The size of each element in the OT extension, in bits.
	 */
	OTExtensionGeneralRInput(vector<byte> sigmaArr, int elementSize) :
		OTExtensionRInput(sigmaArr, elementSize) {
	}

	OTBatchRInputTypes getType() {
		return OTBatchRInputTypes::OTExtensionGeneralRInput;
	}

};



class OTExtensionRandomizedRInput: public OTExtensionRInput{
public:
	OTExtensionRandomizedRInput(vector<byte> sigmaArr, int elementSize) : OTExtensionRInput(sigmaArr,elementSize) {}
	OTBatchRInputTypes getType() override {	return OTBatchRInputTypes::OTExtensionRandomizedRInput;}
};

#ifndef _WIN32
/**
 * Concrete implementation of OT receiver of bristol output.<p>
 * In the bristol scenario, the receiver outputs xSigma as a bitvector.
 * This output class also can be viewed as the output of batch OT when xSigma is a concatenation of all xSigma byte array of all OTs.
 */
class OTExtensionBristolROutput: public OTOnByteArrayROutput {

public:
	OTExtensionBristolROutput(const BitMatrix& receiverOutputMatrix) {

		copy_byte_array_to_byte_vector((byte*)receiverOutputMatrix.squares.data(), receiverOutputMatrix.squares.size()*128*16, xSigma, 0);
	}


};
#endif

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
	virtual shared_ptr<OTBatchROutput> transfer(OTBatchRInput * input) = 0;
	virtual ~OTBatchReceiver() {};
};

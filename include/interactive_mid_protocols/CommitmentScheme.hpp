/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
*/
#pragma once
#include "RandomValue.hpp"
#include "../mid_layer/PlainText.hpp"

/**
* General interface of the receiver's output of the commit phase.
* All receivers have output from the commit phase, that at least includes the commitment id.
*/
class CmtRCommitPhaseOutput: public NetworkSerialized {
public:
	/**
	* Returns the id of the received commitment message.
	*/
	virtual long getCommitmentId() = 0;
};

/**
* Concrete class of receiver's output from the commit phase.
* In the basic case, the receiver outputs the id of the received commitment.
*/
class CmtRBasicCommitPhaseOutput : public CmtRCommitPhaseOutput {
protected:
	long commitmentId;
public:
	/**
	* Constructor that sets the given commitment id.
	*/
	CmtRBasicCommitPhaseOutput(long commitmentId) { this->commitmentId = commitmentId; };
	/**
	* Returns the id of the received commitment message.
	*/
	long getCommitmentId() override { return commitmentId; };
	// network serialization implementation:
	int getSerializedSize() override {return sizeof(long); };
	std::shared_ptr<byte> toByteArray() override {
		byte * result = new byte[sizeof(long)];
		copy(((byte*)&commitmentId), ((byte*)&commitmentId) + sizeof(long), result);
		std::shared_ptr<byte> result_shared(result, std::default_delete<byte[]>());
		return result_shared;
	}
	void initFromByteArray(byte * arr, int size) override {
		memcpy(&commitmentId, arr, sizeof(long));
	};
};

/**
* Concrete class of receiver's output from the commit phase.
* In the trapdoor case, the receiver outputs the id of the received commitment and the trapdoor.
*/
class CmtRTrapdoorCommitPhaseOutput : public CmtRBasicCommitPhaseOutput {
private:
	biginteger trap;
	int serialized_size;
	int trapSize;
public:
	CmtRTrapdoorCommitPhaseOutput() : CmtRTrapdoorCommitPhaseOutput(0, 0) {};
	/**
	* Constructor that sets the given commitment id.
	* @param trapdoor the receiver's trapdoor for this commitment.
	* @param commitmentId the id of the received commitment message.
	*/
	CmtRTrapdoorCommitPhaseOutput(biginteger trapdoor, long commitmentId) :
		CmtRBasicCommitPhaseOutput(commitmentId) {
		this->trap = trapdoor;
		this->trapSize = bytesCount(trap);
		this->serialized_size = trapSize + sizeof(long);
	};
	/**
	* Returns the trapdoor of this commitment.
	*/
	biginteger getTrap() { return trap; };
	
	// network serialization implementation:

	std::shared_ptr<byte> toByteArray() override {
		byte * result = new byte[serialized_size];
		copy(((byte*)&commitmentId), ((byte*)&commitmentId) + sizeof(long), result);
		encodeBigInteger(trap, result + sizeof(long), trapSize);
		std::shared_ptr<byte> result_shared(result, std::default_delete<byte[]>());
		return result_shared;
	}
	int getSerializedSize() override { return serialized_size; };
	void initFromByteArray(byte * arr, int size) override {
		memcpy(&commitmentId, arr, sizeof(long));
		trapSize = size - sizeof(long);
		trap = decodeBigInteger(arr + sizeof(long), trapSize);
		serialized_size = trapSize + sizeof(long);
	};
};

/**
* General interface for commit value.
* Each commit value type (like BigInteger, Byte[], etc) should implement this interface.
*/
class CmtCommitValue {
public:
	/**
	* The committed values can vary, therefore returns a void pointer
	* @return the committed value.
	*/
	virtual std::shared_ptr<void> getX() = 0;
	/**
	* Converts the committed value into a plaintext in order to encrypt it.
	* @return the plaintext contains this commit value.
	*/
	virtual shared_ptr<Plaintext> convertToPlaintext() = 0;
	/**
	* Returns a serializable byte * from this object. Size can be fetched using sendableDataSize()
	*/
	virtual shared_ptr<byte> generateSendableData() = 0;
	virtual int sendableDataSize() = 0;
};

/**
* Concrete implementation of CommitValue where the committed value is a GroupElement.
*/
class CmtGroupElementCommitValue : public CmtCommitValue {
private:
	shared_ptr<GroupElement> x; // the committed value
public:
	/**
	* Constructor that sets the commit value.
	*/
	CmtGroupElementCommitValue(shared_ptr<GroupElement> x) { this->x = x; };
	/**
	* Returns the committed GroupElement. Client needs to cast result to GroupElement*
	*/
	shared_ptr<void> getX() override { return x; }
	/**
	* Converts the committed value to a GroupElementPlaintaxt.
	*/
	shared_ptr<Plaintext> convertToPlaintext() override {
		auto res = make_shared<GroupElementPlaintext>(x);
		return res; 
	};

	/**
	* Returns a serialized object representing this commit value.
	*/
	shared_ptr<byte> generateSendableData() override {
		return x->generateSendableData()->toByteArray(); };
	virtual int sendableDataSize() override {
		return x->generateSendableData()->getSerializedSize(); };
};

/**
* General interface of the committer's commit phase values. <P>
* Classes implementing this interface will hold the value to commit,
* the computed commitment and the random values used for the computation.
*/
class CmtCommitmentPhaseValues {
public:
	/**
	* Returns the random value used for commit the value.
	*/
	virtual shared_ptr<RandomValue> getR()=0;
	/**
	* Returns the committed value.
	*/
	virtual shared_ptr<CmtCommitValue> getX()=0;
	/**
	* The commitment objects can be vary in the different commitment scheme.
	* Therefore, Returns a void pointer.
	*/
	virtual shared_ptr<void> getComputedCommitment()=0;
};

/**
* Concrete implementation of CommitValue where the committed value is a BigInteger.
*/
class CmtBigIntegerCommitValue : public CmtCommitValue {
private:
	biginteger x; // the committed value
	int byteCount;

public:
	/**
	* Constructor that sets the commit value.
	* @param x BigInteger to commit on.
	*/
	CmtBigIntegerCommitValue(biginteger x) { this->x = x; this->byteCount = bytesCount(x); };

	/**
	* Returns the committed BigInteger. Client should cast to biginteger.
	*/
	shared_ptr<void> getX() override { return make_shared<biginteger>(x); };

	/**
	* Converts the committed value to a string.
	*/
	std::string toString() { return (string)x; };

	/**
	* Converts the committed value to a BigIntegerPlaintaxt.
	*/
	shared_ptr<Plaintext> convertToPlaintext() override {
		auto res = make_shared<BigIntegerPlainText>(x);
		return res;
	};

	/**
	* Returns a serialized object representing this commit value.
	*/
	shared_ptr<byte> generateSendableData() override {
		std::shared_ptr<byte> output(new byte[byteCount], std::default_delete<byte[]>());
		encodeBigInteger(x, output.get(), byteCount);
		return output;
	};
	int sendableDataSize() override { return byteCount; }
};

/**
* Concrete implementation of CommitValue where the committed value is a byte*.
*/
class CmtByteArrayCommitValue : public CmtCommitValue {
private:
	std::shared_ptr<byte> x; // the committed value
	int len; 
public:
	/**
	* Constructor that sets the commit value.
	*/
	CmtByteArrayCommitValue(std::shared_ptr<byte> x, int len) { this->x = x; this->len = len; };
	/**
	* Returns the committed byte*. client need to cast to byte*
	*/
	shared_ptr<void> getX() override{ return x; }
	int getXSize() { return len; };
	/**
	* Converts the committed value to a string.
	*/
	string toString() { return std::string(reinterpret_cast<char const*>(x.get()), len); };
	/**
	* Converts the committed value to a ByteArrayPlaintext.
	*/
	shared_ptr<Plaintext> convertToPlaintext() override {
		auto res = make_shared<ByteArrayPlaintext>(x, len);
		return res;
	};
	/**
	* Returns a serialized object representing this commit value.
	*/
	std::shared_ptr<byte> generateSendableData() override {return x;}
	int sendableDataSize() override { return len; }
};

/**
* This interface represents the commitment message sent from the committer to the receiver
* during the commitment phase.
* Every commitment has an id needed to identify the specific commitment in the case that many
* commitments are performed by the committer without decommiting in between the commitments.
* Each commitment has an id attached to it used lated for decommitment.
*/
class CmtCCommitmentMsg : public NetworkSerialized {
public:
	/**
	* Returns the unique id of the commitment.
	*/
	virtual long getId()=0;
	/**
	* The commitment objects can vary, therefore returns an void pointer.
	* @return the commitment object.
	*/
	virtual shared_ptr<void> getCommitment()=0;
};	

/**
* General interface for the decommitment message the committer sends to the receiver.
*/
class CmtCDecommitmentMessage : public NetworkSerialized{
public:
	/**
	* Returns the committed value.
	* @return the serializable committed value.
	*/
	virtual shared_ptr<byte> getSerializedX() = 0;
	virtual int getSerializedXSize() = 0;
	/**
	* Returns the random value used to commit.
	*/
	virtual shared_ptr<RandomValue> getR() = 0;

};

/**
* This the general interface of the Committer side of a Commitment Scheme.
* A commitment scheme has a commitment phase in which the committer send the commitment to the
* Receiver; and a decommitment phase in which the the Committer sends the decommitment to the Receiver.
*/
class CmtCommitter {
public:
	/**
	* Generate a commitment message using the given input and ID.<p>
	* There are cases when the user wants to commit on the input but remain non-interactive,
	* meaning not to send the generate message yet.
	* The reasons for doing that are vary, for example the user wants to prepare a lot
	* of commitments and send together.
	* In these cases the commit function is not useful since it sends the generates commit message
	* to the other party. <p>
	* This function generates the message without sending it and this allows the user to save it
	* and send it later if he wants.<p>
	* In case the commit phase is interactive, the commit message cannot be generated and an
	* IllegalStateException will be thrown.
	* In this case one should use the commit function instead.
	*
	* Code example: giving a committer object and an input,
	*
	* // create three commitment messages.
	* CmtCCommitmentMsg* msg1 = generateCommitmentMsg(input, 1);
	* CmtCCommitmentMsg* msg2 = generateCommitmentMsg(input, 2);
	* CmtCCommitmentMsg* msg3 = generateCommitmentMsg(input, 3);
	* ...
	*
	* try {
	*		// Send the messages by the channel.
	*		channel.write(msg1);
	*		channel.write(msg2);
	*		channel.write(msg3);
	*	} catch (const logic_error& e) {
	*		// should remove the failed commitment from the commitmentMap!
	*		cerr << failed to send the commitment. The error is: " <<  e.what();
	*	}
	*
	* @param input The value that the committer commits about.
	* @param id Unique value attached to the input to keep track of the commitments in the case 
	* that many commitments are performed one after the other without decommiting them yet.
	* @return the generated commitment object.
	*/
	virtual shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(shared_ptr<CmtCommitValue> input, long id)=0;

	/**
	* This function is the heart of the commitment phase from the Committer's point of view.
	* @param input The value that the committer commits about.
	* @param id Unique value attached to the input to keep track of the commitments in
	* the case that many commitments are performed one after the other without decommiting them yet.
	*/
	virtual void commit(shared_ptr<CmtCommitValue> input, long id) = 0;

	/**
	* Generate a decommitment message using the given id.<p>
	*
	* There are cases when the user wants to decommit but remain non-interactive, meaning not to
	* send the generate message yet.
	* The reasons for doing that are vary, for example the user wants to prepare a lot of 
	* decommitments and send together.
	* In these cases the decommit function is not useful since it sends the generates decommit
	* message to the other party. <p>
	* This function generates the message without sending it and this allows the user to save it
	* and send it later if he wants.<p>
	* In case the decommit phase is interactive, the decommit message cannot be generated and an 
	* IllegalStateException will be thrown.
	* In this case one should use the decommit function instead.
	*
	* Code example: giving a committer object and an input,
	*
	* //Create three commitment messages.
	* CmtCDecommitmentMessage* msg1 = generateDecommitmentMsg(1);
	* CmtCDecommitmentMessage* msg2 = generateDecommitmentMsg(2);
	* CmtCDecommitmentMessage* msg3 = generateDecommitmentMsg(3);
	* ...
	*
	* try {
	*		// Send the messages by the channel.
	*		channel.write(msg1);
	*		channel.write(msg2);
	*		channel.write(msg3);
	*	} catch (const logic_error& e) {
	*		cerr << "failed to send the decommitment. The error is: " <<  e.what();
	*	}
	*
	* @param id Unique value attached to the input to keep track of the commitments in the case
	* that many commitments are performed one after the other without decommiting them yet.
	* @return the generated decommitment object.
	*/
	virtual shared_ptr<CmtCDecommitmentMessage> generateDecommitmentMsg(long id)=0;

	/**
	* This function is the heart of the decommitment phase from the Committer's point of view.
	* @param id Unique value used to identify which previously committed value needs to be decommitted now.
	*/
	virtual void decommit(long id) = 0;

	/**
	* This function samples random commit value to commit on.
	* @return the sampled commit value.
	*/
	virtual shared_ptr<CmtCommitValue> sampleRandomCommitValue() =0;

	/**
	* This function wraps the raw data x with a suitable CommitValue instance according to the
	* actual implementaion.
	* @param x array to convert into a commitValue.
	* @return the created CommitValue.
	*/
	virtual shared_ptr<CmtCommitValue>  generateCommitValue(shared_ptr<byte> x, int len) =0;

	/**
	* This function converts the given commit value to a byte array.
	* @param value to get its bytes.
	* @return the generated bytes.
	*/
	virtual pair<shared_ptr<byte>,int> generateBytesFromCommitValue(
		shared_ptr<CmtCommitValue> value)=0;

	/**
	* This function returns the values calculated during the preprocess phase.<p>
	* This function is used for protocols that need values of the commitment,
	* like ZK protocols during proofs on the commitment.
	* We recommended not to call this function from somewhere else.
	* @return values calculated during the preprocess phase
	*/
	virtual void** getPreProcessValues() = 0;
	virtual int getPreProcessValuesSize() = 0;

	/**
	* This function returns the values calculated during the commit phase for a specific commitment.<p>
	* This function is used for protocols that need values of the commitment,
	* like ZK protocols during proofs on the commitment.
	* We recommended not to call this function from somewhere else.
	* @param id of the specific commitment
	* @return values calculated during the commit phase
	*/
	virtual shared_ptr<CmtCommitmentPhaseValues> getCommitmentPhaseValues(long id) = 0;
};

/**
* This the general interface of the Receiver side of a Commitment Scheme. 
* A commitment scheme has a commitment phase in which the Receiver waits for the commitment
* sent by the Committer; and a decommitment phase in which the Receiver waits for the decommitment
* sent by the Committer and checks whether to accept or reject the decommitment.
*/
class CmtReceiver {
public:
	/**
	* This function is the heart of the commitment phase from the Receiver's point of view.
	* @return the id of the commitment and some other information if necessary according to the 
	* implementing class.
	*/
	virtual shared_ptr<CmtRCommitPhaseOutput> receiveCommitment() = 0;

	/**
	* This function is the heart of the decommitment phase from the Receiver's point of view.
	* @param id wait for a specific message according to this id
	* @return the commitment
	*/
	virtual shared_ptr<CmtCommitValue> receiveDecommitment(long id) = 0;

	/**
	* Verifies the given decommitment object according to the given commitment object.<p>
	*
	* There are cases when the committer sends the commitment and decommitments in the application,
	* and the receiver does not use the receiveCommitment and receiveDecommitment function.
	* In these cases this function should be called for each pair of commitment and decommitment
	* messages.
	* The reasons for doing that are vary, for example a protocol that prepare a lot of
	* commitments and send together.
	* In these cases the receiveCommitment and receiveDecommitment functions are not useful
	* since it receives the generates messages separately. to the other party. <p>
	* This function generates the message without sending it and this allows the user to save
	* it and send it later if he wants.<p>
	* In case the decommit phase is interactive, the decommit message cannot be generated 
	* and an IllegalStateException will be thrown.
	* In this case one should use the decommit function instead.
	*
	* Code example: giving a committer object and an input,
	*
	* //Create three commitment messages.
	* CmtCDecommitmentMessage msg1 = generateDecommitmentMsg(1);
	* CmtCDecommitmentMessage msg2 = generateDecommitmentMsg(2);
	* CmtCDecommitmentMessage msg3 = generateDecommitmentMsg(3);
	* ...
	*
	*		//Send the messages by the channel.
	*		channel->write_fast(msg1);
	*		channel->write_fast(msg2);
	*		channel->write_fast(msg3);
	*
	*
	* @param commitmentMsg the commitment object.
	* @param decommitmentMsg the decommitment object
	* @return the committed value if the decommit succeeded; null, otherwise.
	*/
	virtual shared_ptr<CmtCommitValue> verifyDecommitment(shared_ptr<CmtCCommitmentMsg> commitmentMsg,
		shared_ptr<CmtCDecommitmentMessage> decommitmentMsg) = 0;

	/**
	* Return the values used during the pre-process phase (usually upon construction). 
	* Since these values vary between the different implementations this function
	* returns a general array of void pointers.
	*/
	virtual void** getPreProcessedValues() = 0;
	virtual int getPreProcessedValuesSize() = 0;

	/**
	* Return the intermediate values used during the commitment phase.
	* @param id get the commitment values according to this id.
	* @return a general void pointer.
	*/
	virtual shared_ptr<void> getCommitmentPhaseValues(long id) = 0;

	/**
	* This function converts the given commit value to a byte array.
	* @param value to get its bytes.
	* @return a shared pointer to the generated bytes + the array size
	*/
	virtual pair<shared_ptr<byte>, int> generateBytesFromCommitValue(shared_ptr<CmtCommitValue> value)=0;
};

/**
* This interface is used by the committer to prove that:<p>
* 1. The committer knows the committed value.<p>
* 2. The committed value was x.<p>
*
* All commitment scheme that have proofs should implement this interface.
*/
class CmtWithProofsCommitter : public CmtCommitter {
public:
	/**
	* Proves that the committer knows the committed value.
	* @param id of the commitment message.
	*/
	virtual void proveKnowledge(long id) = 0;

	/**
	* Proves that the committed value with the given id was x.
	* @param id of the committed value.
	*/
	virtual void proveCommittedValue(long id) = 0;
};

/**
* This interface is used by the verifier to verify that:<p>
* 1. The committer knows the committed value.<p>
* 2. The committed value was x.<p>
* All commitment scheme that have proofs should implement this interface.
*/
class CmtWithProofsReceiver : CmtReceiver {
public:
	/**
	* Verifies that the committer knows the committed value.
	* @param id of the commitment message.
	*/
	virtual bool verifyKnowledge(long id) = 0;

	/**
	* Verifies that the committed value with the given id was x.
	* @param id of the committed value.
	*/
	virtual shared_ptr<CmtCommitValue> verifyCommittedValue(long id) = 0;
};

/**
* Marker interface.
* Each committer/receiver that implement this interface is marked as committer/receiver
* that commit on a BigInteger.
*/
class CmtOnBigInteger {};

/**
* Marker interface.
* Each committer/receiver that implement this interface is marked as committer/receiver
* that commit on a byte array.
*/
class CmtOnByteArray {};

/**
* Marker interface.
* Each committer/receiver that implement this interface is marked as committer/receiver
* that commit on a GroupElement.
*/
class CmtOnGroupElement {};

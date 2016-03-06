#pragma once
#include "../infra/Common.hpp"
#include "../primitives/SecurityLevel.hpp"
#include "../comm/TwoPartyComm.hpp"
#include <openssl/rand.h>


/**
* Marker interface. Each concrete ZK prover's input class should implement this interface.
*/
class ZKProverInput {
public:
	virtual ~ZKProverInput() {};
};
/**
* This interface is a marker interface for Zero Knowledge input, 
* where there is an implementing class
* for each concrete Zero Knowledge protocol.
*/
class ZKCommonInput {
public:
	virtual ~ZKCommonInput() {};
};
/**
* Marker interface for common input of Sigma Protocols.<p>
* Each Sigma Protocol has a common input for the prover and the verifier, 
* such input should implement this interface.
*/
class SigmaCommonInput : public ZKCommonInput {};
/**
* Every Sigma protocol prover needs inputs during the protocol execution, but every concrete
* prover needs different inputs.<p>
* This interface is a marker interface for Sigma protocol input, 
* where there is an implementing class for each concrete Sigma protocol.
*/
class SigmaProverInput : public ZKProverInput {
public:
	/**
	* Returns the common parameters of the prover and the verifier.
	*/
	virtual shared_ptr<SigmaCommonInput> getCommonParams()=0;
};
/**
* Marker interface. Every Sigma prover or verifier that consists of 
* DamgardJurik should implement this interface.
*/
class DJBasedSigma {};
/**
* Marker interface. Every Sigma prover or verifier that consists of DlogGroup
* should implement this interface.
*/
class DlogBasedSigma {};
/**
* Every Sigma protocol prover/receiver needs to send messages during the protocol execution.<p>
* This interface is a marker interface for Sigma protocol message, where there
* is an implementing class for each concrete Sigma message, 
* like GroupElement message or BigInteger message.
*/
class SigmaProtocolMsg : public NetworkSerialized {};

/**
* General interface for Sigma Protocol prover. Every class that implements it is signed as 
* Sigma Protocol prover.<p>
*
* Sigma protocols are a basic building block for zero-knowledge, 
* zero-knowledge proofs of knowledge and more. <p>
* A sigma protocol is a 3-round proof, comprised of a first message from
* the prover to the verifier, a random challenge from the verifier and a second message 
* from the prover. <p>
* See Hazay-Lindell (chapter 6) for more information.
*/
class SigmaProtocolProver {
public:
	/**
	* Runs the proof of this protocol. <p>
	* This function executes the proof at once by calling the following functions one by one. <p>
	* This function can be called when a user does not want to save time by 
	* doing operations in parallel. <p>
	*/
	virtual void prove(shared_ptr<SigmaProverInput> input) = 0;
	/**
	* Processes the first step of the sigma protocol. <p>
	* It computes the first message and sends it to the verifier.
	*/
	virtual void processFirstMsg(shared_ptr<SigmaProverInput> input)=0;
	/**
	* Processes the second step of the sigma protocol. <p>
	* It receives the challenge from the verifier, computes the second message and then 
	* sends it to the verifier. <p>
	* This is a blocking function!
	*/
	virtual void processSecondMsg() =0;
};

/**
 * Every sigma simulator outputs the result in the end of it's compute function, but each 
 * one can outputs different values. <p>
 * This interface is a marker interface for Sigma simulator output, where there is an 
 * implementing class
 * for each concrete Sigma protocol.
 */
class SigmaSimulatorOutput {
public:
	/**
	* All SigmaSimulators contains first message, challenge and second message. 
	* Returns the first message.
	* @return a - first message
	*/
	virtual shared_ptr<SigmaProtocolMsg> getA()=0;

	/**
	* All SigmaSimulators contains first message, challenge and second message. 
	* Returns the challenge 
	*/
	virtual shared_ptr<byte> getE() = 0 ;

	/**
	* All SigmaSimulators contains first message, challenge and second message.
	* Returns the challenge size
	*/
	virtual int getESize() = 0;

	/**
	* All SigmaSimulators contains first message, challenge and second message. 
	* Returns the second message.
	* @return z - second message
	*/
	virtual shared_ptr<SigmaProtocolMsg> getZ() = 0;
};

/**
* General interface for Sigma Protocol Simulator. <p>
* The simulator is a probabilistic polynomial-time function, that on input x and 
* challenge e outputs
* a transcript of the form (a, e, z) with the same probability distribution as transcripts
* between the honest prover and verifier on common input x.
*/
class SigmaSimulator {
public:
	/**
	* Computes the simulator computation.
	*/
	virtual shared_ptr<SigmaSimulatorOutput> simulate(shared_ptr<SigmaCommonInput> input,
		shared_ptr<byte> challenge, int challenge_size)  =0;

	/**
	* Chooses random challenge and computes the simulator computation.
	*/
	virtual shared_ptr<SigmaSimulatorOutput> simulate(shared_ptr<SigmaCommonInput> input) = 0;
	/**
	* Returns the soundness parameter for this Sigma simulator.
	*/
	virtual int getSoundnessParam() = 0;
};

/**
* General interface for Sigma Protocol verifier. Every class that implements it is
* signed as Sigma Protocol verifier.<p>
* Sigma protocols are a basic building block for zero-knowledge, zero-knowledge proofs
* of knowledge and more. <p>
* A sigma protocol is a 3-round proof, comprised of a first message from the prover to
* the verifier,
* a random challenge from the verifier and a second message from the prover. <p>
* See Hazay-Lindell (chapter 6) for more information.
*/
class SigmaProtocolVerifier {
	/**
	* Runs the verification of this protocol. <p>
	* This function executes the verification protocol at once by calling the following.
	* functions one by one.<p>
	* This function can be called when a user does not want to save time by doing operations
	* in parallel.
	*/
	virtual bool verify(shared_ptr<SigmaCommonInput> input) = 0;
	/**
	* Samples the challenge for this protocol.
	*/
	virtual void sampleChallenge()=0;
	/**
	* Waits for the prover's first message and then sends the chosen challenge to the prover.<p>
	* This is a blocking function!
	*/
	virtual void sendChallenge() = 0;
	/**
	* Waits to the prover's second message and then verifies the proof.	<p>
	* This is a blocking function!
	*/
	virtual bool processVerify(shared_ptr<SigmaCommonInput> input) = 0;
	/**
	* Sets the given challenge 
	*/
	virtual void setChallenge(shared_ptr<byte> challenge, int challenge_size)=0;
	/**
	* Return the challenge byte array
	*/
	virtual pair<shared_ptr<byte>, int> getChallenge()=0;
};

/**
* This interface manages the mathematical calculations of the prover side in the sigma protocol.<p>
* It samples random values and computes the messages.
*/
class SigmaProverComputation {
public:
	/**
	* Computes the first message of the sigma protocol.
	*/
	virtual shared_ptr<SigmaProtocolMsg> computeFirstMsg(shared_ptr<SigmaProverInput> input) =0;
	/**
	* Computes the second message of the sigma protocol.
	*/
	virtual shared_ptr<SigmaProtocolMsg> computeSecondMsg(byte* challenge, int challenge_size) =0;
	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	virtual int getSoundnessParam() = 0;
	/**
	* Returns the simulator that matches this sigma protocol prover.
	*/
	virtual shared_ptr<SigmaSimulator> getSimulator() = 0;
};

/**
* This interface manages the mathematical calculations of the verifier side in the sigma protocol.<p>
* It samples random challenge and verifies the proof.
*/
class SigmaVerifierComputation {
public:
	/**
	* Samples the challenge for this protocol.
	*/
	virtual void sampleChallenge() =0;
	/**
	* Verifies the proof.
	* @param input
	* @return true if the proof has been verified; false, otherwise.
	*/
	virtual bool verify(shared_ptr<SigmaCommonInput> input, 
		shared_ptr<SigmaProtocolMsg> a, shared_ptr<SigmaProtocolMsg> z) =0;
	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	virtual int getSoundnessParam() = 0;
	/**
	* Sets the given challenge.
	* @param challenge
	*/
	virtual void setChallenge(shared_ptr<byte> challenge, int challenge_size) = 0;
	/**
	* @return the challenge.
	*/
	virtual pair<shared_ptr<byte>, int> getChallenge() = 0;
};

/**
* This class manages the communication functionality of all the sigma protocol provers.<p>
* It sends the first message, receives the challenge from the prover and sends the second message.<p>
* It uses SigmaComputation instance of a concrete sigma protocol to compute the actual messages.
*/
class SigmaProver : public SigmaProtocolProver {
public:
	/*
	* This class manages the structure of all sigma provers:
	* Prover message 1 (a):	SAMPLE a random values
	*  						COMPUTE first message
	*  						SEND the computed message to the verifier
	* Prover message 2 (z):	RECEIVE challenge from verifier
	* 							COMPUTE second message
	* 							SEND the computed message to the verifier
	*
	* The actual computation of the messages is done by sigmaComputation class member.
	*/

	/**
	* Constructor that sets the given channel and sigmaProverComputation.
	*/
	SigmaProver(std::shared_ptr<ChannelServer> channel,
		std::shared_ptr<SigmaProverComputation> proverComputation) {
		this->channel = channel;
		this->proverComputation = proverComputation;
	}
	void prove(shared_ptr<SigmaProverInput> input) override{
		processFirstMsg(input); // step one of the protocol.
		processSecondMsg(); // step two of the protocol.
	};
	/**
	* Processes the first step of the sigma protocol.<p>
	*  "SAMPLE a random values <p>
	* 	 COMPUTE first message<p>
	* 	 SEND the computed message to the verifier".<p>
	* It computes the first message and sends it to the verifier.
	*/
	void processFirstMsg(shared_ptr<SigmaProverInput> input) override;
	/**
	* Processes the second step of the sigma protocol.<p>
	* 	"RECEIVE challenge from verifier<p>
	* 	 COMPUTE second message<p>
	* 	 SEND the computed message to the verifier".<p>
	* This is a blocking function!
	*/
	 void processSecondMsg() override;


private:
	std::shared_ptr<ChannelServer> channel;
	std::shared_ptr<SigmaProverComputation> proverComputation;	// underlying sigma computation.
	bool doneFirstMsg;
	/**
	* Sends the given message to the verifier.
	*/
	void sendMsgToVerifier(shared_ptr<SigmaProtocolMsg> message) { 
		auto raw_message = message->toByteArray();
		int message_size = message->getSerializedSize();
		channel->write_fast(raw_message.get(), message_size);
	};
};


/**
* This class manages the communication functionality of all the sigma protocol verifiers,
* such as send the challenge to the prover and receive the prover messages. <p>
* It uses SigmaVerifierComputation instance of a concrete sigma protocol to compute the actual calculations.
*/
class SigmaVerifier : public SigmaProtocolVerifier {

	/*
	* This class manages the common functionality of all sigma verifiers:
	* 	Verifier challenge (e):	SAMPLE a random challenge e
	* 							RECEIVE first message from the prover
	* 							SEND challenge to prover
	* 	Verifier check:			RECEIVE second message from the prover
	* 							VERIFY proof.
	*/

public:
	/**
	* Constructor that sets the given channel and random.
	*/
	SigmaVerifier(shared_ptr<ChannelServer> channel, shared_ptr<SigmaVerifierComputation> verifierComputation,
		shared_ptr<SigmaProtocolMsg> emptyFirstMessage, shared_ptr<SigmaProtocolMsg> emptySecondMessage) {
		this->channel = channel;
		this->verifierComputation = verifierComputation;
		this->a = emptyFirstMessage;
		this->z = emptySecondMessage;
	}
	bool verify(shared_ptr<SigmaCommonInput> input) override;
	void sampleChallenge() override {
		// delegates to the underlying verifierComputation object.
		verifierComputation->sampleChallenge();
	}
	void setChallenge(shared_ptr<byte> challenge, int challenge_size) override{
		// delegates to the underlying verifierComputation object.
		verifierComputation->setChallenge(challenge, challenge_size);
	}
	pair<shared_ptr<byte>,int> getChallenge() override {
		// delegates to the underlying verifierComputation object.
		return verifierComputation->getChallenge();
	}
	void sendChallenge() override;
	bool processVerify(shared_ptr<SigmaCommonInput> input) override;

private:
	shared_ptr<ChannelServer> channel;
	shared_ptr<SigmaVerifierComputation> verifierComputation;
	shared_ptr<SigmaProtocolMsg> a;	// first message from the prover.
	shared_ptr<SigmaProtocolMsg> z;	// second message from the prover.
	bool doneChallenge;
	/**
	* Waits for message from receiver and returns it.
	* Fills an instance of SigmaProtocolMsg with body from the received message
	*/
	void receiveMsgFromProver(shared_ptr<SigmaProtocolMsg> msg);
	/**
	* Sends the challenge to the prover.
	*/
	void sendChallengeToProver(byte* challenge, int challenge_size) {
		channel->write_fast(challenge, challenge_size);
	}
};

/**
* Concrete implementation of SigmaProtocol message. <p>
* This message contains array of SigmaProtocolMsg and used, for example, when the SigmaANDProver
* sends the messages to the verifier.<p>
*/
class SigmaMultipleMsg : public SigmaProtocolMsg {
public:
	SigmaMultipleMsg(vector<shared_ptr<SigmaProtocolMsg>> messages) { this->messages = messages; };
	vector<shared_ptr<SigmaProtocolMsg>> getMessages() { return messages; };
	void initFromByteArray(byte* arr, int size) override;
	shared_ptr<byte> toByteArray() override;
	int getSerializedSize() override;

private:
	vector<shared_ptr<SigmaProtocolMsg>> messages;
};

/**
* Concrete implementation of SigmaProtocol message. <p>
* This message contains one BigInteger value and used when the prover sends a message to the verifier.
*/
class SigmaBIMsg : public SigmaProtocolMsg {
private:
	biginteger z;
	int size_;
public:
	SigmaBIMsg() { this->z = -100; };
	SigmaBIMsg(biginteger z) { this->z = z; };
	biginteger getMsg() { return z; };

	// SerializedNetwork implementation:
	void initFromByteArray(byte* arr, int size) override {
		z = decodeBigInteger(arr, size); 
		size_ = size;
	};
	shared_ptr<byte> toByteArray() override {
		size_ = bytesCount(this->z);
		std::shared_ptr<byte> res(new byte[size_], std::default_delete<byte[]>());
		encodeBigInteger(this->z, res.get(), size_);
		return res;
	}
	int getSerializedSize() override { return size_; };
};

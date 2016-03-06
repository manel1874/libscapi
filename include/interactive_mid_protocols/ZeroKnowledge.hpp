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
#include "SigmaProtocol.hpp"
#include "CommitmentSchemePedersen.hpp"

/**
* A zero-knowledge proof or zero-knowledge protocol is a method by which one party (the prover) 
* can prove to another party (the verifier) that a given statement is true, without conveying 
* any additional information apart from the fact that the statement is indeed true.<p>
*
* This interface is a general interface that simulates the prover side of the Zero Knowledge proof.
* Every class that implements it is signed as Zero Knowledge prover.
*/
class ZKProver {
public:
	/**
	* Runs the prover side of the Zero Knowledge proof.
	* @param input holds necessary values to the proof calculations.
	*/
	virtual void prove(shared_ptr<ZKProverInput> input) = 0;
};

/**
* This interface is a general interface that simulates the prover side of the 
* Zero Knowledge proof of knowledge. <p>
* Every class that implements it is signed as ZKPOK prover.
*/
class ZKPOKProver : public ZKProver {};

/**
* A zero-knowledge proof or zero-knowledge protocol is a method by which one party (the prover)
* can prove to another party (the verifier) that a given statement is true, without conveying
* any additional information apart from the fact that the statement is indeed true.<p>
*
* This interface is a general interface that simulates the verifier side of the 
* Zero Knowledge proof.
* Every class that implements it is signed as Zero Knowledge verifier.
*/
class ZKVerifier {
public:
	/**
	* Runs the verifier side of the Zero Knowledge proof.
	* @param input holds necessary values to the varification calculations.
	* @return true if the proof was verified; false, otherwise.
	*/
	virtual bool verify(shared_ptr<ZKCommonInput> input, shared_ptr<SigmaProtocolMsg> emptyA,
		shared_ptr<SigmaProtocolMsg> emptyZ) = 0;
};

/**
* This interface is a general interface that simulates the verifier side of the 
* Zero Knowledge proof of knowledge. <p>
* Every class that implements it is signed as ZKPOK verifier.
*/
class ZKPOKVerifier : public ZKVerifier {};

/**
* Concrete implementation of Zero Knowledge prover.<p>
* This is a transformation that takes any Sigma protocol and any perfectly hiding 
* commitment scheme and yields a zero-knowledge proof.<P>
* For more information see Protocol 6.5.1, page 161 of Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 2.1 of pseudo codes document
* at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class ZKFromSigmaProver : ZKProver {
public:
	/**
	* Constructor that accepts the underlying channel, sigma protocol's prover and 
	* commitment's receiver to use.
	* @param channel used to communicate between prover and verifier.
	* @param sProver underlying sigma prover to use.
	* @param receiver Must be an instance of PerfectlyHidingCT
	*/
	ZKFromSigmaProver(shared_ptr<ChannelServer> channel, shared_ptr<SigmaProverComputation> sProver,
		shared_ptr<CmtReceiver> receiver);

	/**
	* Constructor that accepts the underlying channel, sigma protocol's prover and
	* sets default commitment's receiver.
	* @param channel used to communicate between prover and verifier.
	* @param sProver underlying sigma prover to use.
	*/
	ZKFromSigmaProver(shared_ptr<ChannelServer> channel, shared_ptr<SigmaProverComputation> sProver) {
		this->sProver = sProver;
		this->receiver = make_shared<CmtPedersenReceiver>(channel);
		this->channel = channel;
	};

	/**
	* Runs the prover side of the Zero Knowledge proof.<p>
	* Let (a,e,z) denote the prover1, verifier challenge and prover2 messages
	* of the sigma protocol.<p>
	* This function computes the following calculations:<p>
	*
	*		 RUN the receiver in COMMIT.commit <p>
	*		 COMPUTE the first message a in sigma, using (x,w) as input<p>
	*		 SEND a to V<p>
	*		 RUN the receiver in COMMIT.decommit <p>
	*			IF COMMIT.decommit returns some e<p>
	*     			COMPUTE the response z to (a,e) according to sigma<p>
	*      		SEND z to V<p>
	*      		OUTPUT nothing<p>
	*			ELSE (IF COMMIT.decommit returns INVALID)<p>
	*      		OUTPUT ERROR (CHEAT_ATTEMPT_BY_V)<p>
	* @param input must be an instance of SigmaProverInput.
	*/
	void prove(shared_ptr<ZKProverInput> input) override;

private:
	shared_ptr<ChannelServer> channel;
	// underlying prover that computes the proof of the sigma protocol:
	shared_ptr<SigmaProverComputation> sProver;
	shared_ptr<CmtReceiver> receiver; //Underlying Commitment receiver to use.

	/**
	* Runs the receiver in COMMIT.commit with P as the receiver.
	*/
	shared_ptr<CmtRCommitPhaseOutput> receiveCommit() { return receiver->receiveCommitment(); };

	/**
	* Processes the first message of the Zero Knowledge protocol:
	*  "COMPUTE the first message a in sigma, using (x,w) as input
	*	SEND a to V".
	* @param input
	*/
	void processFirstMsg(shared_ptr<SigmaProverInput> input) {
		// compute the first message by the underlying proverComputation.
		auto a = sProver->computeFirstMsg(input);
		// send the first message.
		sendMsgToVerifier(a);
	}

	/**
	* Runs the receiver in COMMIT.decommit
	* If decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	* @param l
	* @param ctOutput
	*/
	pair<shared_ptr<byte>, int> receiveDecommit(long id) {
		auto val = receiver->receiveDecommitment(id);
		if (!val) 
			throw CheatAttemptException("Decommit phase returned invalid");
		return receiver->generateBytesFromCommitValue(val);
	}

	/**
	* Processes the second message of the Zero Knowledge protocol:
	* 	"COMPUTE the response z to (a,e) according to sigma
	*   SEND z to V
	*   OUTPUT nothing".
	* This is a blocking function!
	*/
	void processSecondMsg(byte* e, int eSize) {
		// compute the second message by the underlying proverComputation.
		auto z = sProver->computeSecondMsg(e, eSize);
		// send the second message.
		sendMsgToVerifier(z);
	}

	/**
	* Sends the given message to the verifier.
	* @param message to send to the verifier.
	*/
	void sendMsgToVerifier(shared_ptr<SigmaProtocolMsg> message) {
		shared_ptr<byte> raw_message = message->toByteArray();
		int message_size = message->getSerializedSize();
		channel->write_fast(raw_message.get(), message_size);
	};
};

/**
* Concrete implementation of Zero Knowledge verifier.<p>
* This is a transformation that takes any Sigma protocol and any perfectly hiding 
* commitment scheme and yields a zero-knowledge proof.<p>
* For more information see Protocol 6.5.1, page 161 of Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 2.1 of pseudo 
* codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class ZKFromSigmaVerifier : ZKVerifier {
public:
	/**
	* Constructor that accepts the underlying channel, sigma protocol's verifier 
	* and committer to use.
	* @param channel used to communicate between prover and verifier.
	* @param sVerifier underlying sigma verifier to use.
	* @param committer Must be an instance of PerfectlyHidingCT
	*/
	ZKFromSigmaVerifier(shared_ptr<ChannelServer> channel, shared_ptr<SigmaVerifierComputation> sVerifier,
		shared_ptr<CmtCommitter> committer, std::mt19937_64 random);

	/**
	* Constructor that accepts the underlying channel, sigma protocol's verifier and
	* sets default committer.
	* @param channel used to communicate between prover and verifier.
	* @param sVerifier underlying sigma verifier to use.
	*/
	ZKFromSigmaVerifier(shared_ptr<ChannelServer> channel,
		shared_ptr<SigmaVerifierComputation> sVerifier, std::mt19937_64 random) {
		this->sVerifier = sVerifier;
		this->committer = make_shared<CmtPedersenCommitter>(channel);
		this->channel = channel;
		this->random = random;
	}

	/**
	* Runs the verifier side of the Zero Knowledge proof.<p>
	* Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.<p>
	* This function computes the following calculations:<p>
	*
	*		 SAMPLE a random challenge  e <- {0, 1}^t <p>
	*		 RUN COMMIT.commit as the committer with input e<p>
	*		 WAIT for a message a from P<p>
	*		 RUN COMMIT.decommit as the decommitter<p>
	* 		 WAIT for a message z from P<p>
	* 		 IF  transcript (a, e, z) is accepting in sigma on input x<p>
	*			OUTPUT ACC<p>
	*		 ELSE<p>
	*	 	    OUTPUT REJ<p>
	* @param input must be an instance of SigmaCommonInput.
	*/
	bool verify(shared_ptr<ZKCommonInput> input, shared_ptr<SigmaProtocolMsg> emptyA, 
		shared_ptr<SigmaProtocolMsg> emptyZ) override;

private:
	shared_ptr<ChannelServer> channel;
	// underlying verifier that computes the proof of the sigma protocol.
	shared_ptr<SigmaVerifierComputation> sVerifier;
	shared_ptr<CmtCommitter> committer;	// underlying Commitment committer to use.
	std::mt19937_64 random;

	/**
	* Runs COMMIT.commit as the committer with input e.
	* @param e
	*/
	long commit(shared_ptr<byte> e, int eSize) {
		auto val = committer->generateCommitValue(e, eSize);
		long id = random();
		committer->commit(val, id);
		return id;
	}

	/**
	* Waits for a message a from the prover.
	* @return the received message
	*/
	void receiveMsgFromProver(shared_ptr<SigmaProtocolMsg> concreteMsg);

	/**
	* Runs COMMIT.decommit as the decommitter.
	* @param id
	*/
	void decommit(long id) { committer->decommit(id); };

	/**
	* Verifies the proof.
	* @param input
	* @param a first message from prover.
	*/
	bool proccessVerify(
		shared_ptr<SigmaCommonInput> input, shared_ptr<SigmaProtocolMsg> a,
		shared_ptr<SigmaProtocolMsg> z) {
		// wait for a message z from P, 
		// if transcript (a, e, z) is accepting in sigma on input x, output ACC
		// else outupt REJ
		receiveMsgFromProver(z);
		return sVerifier->verify(input, a, z);
	};
};

// Forward decleration
class ZKPOKFromSigmaCmtPedersenProver;
class ZKPOKFromSigmaCmtPedersenVerifier;

/**
* Concrete implementation of committer with proofs.
* This implementation uses ZK based on SigmaPedersenKnowledge and SIgmaPedersenCommittedValue.
*/
class CmtPedersenWithProofsCommitter : public CmtPedersenCommitter, public CmtWithProofsCommitter {
private:
	// proves that the committer knows the committed value.
	shared_ptr<ZKPOKFromSigmaCmtPedersenProver> knowledgeProver;
	// proves that the committed value is x.
	// usually, if the commitment scheme is PerfectlyBinding secure, than a ZK is used to prove committed value.
	// in Pedersen, this is not the case since Pedersen is not PerfectlyBinding secure.
	// in order to be able to use the Pedersen scheme we need to prove committed value with ZKPOK instead.
	shared_ptr<ZKPOKFromSigmaCmtPedersenProver> committedValProver;

	/**
	* Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
	* @param t
	*/
	void doConstruct(int t);

public:
	/**
	* Default constructor that gets the channel and creates the ZK provers with default Dlog group.
	* @param channel
	*/
	CmtPedersenWithProofsCommitter(shared_ptr<ChannelServer> channel, int statisticalParamater) :
		CmtPedersenCommitter(channel) {
		doConstruct(statisticalParamater);
	};

	/**
	* Constructor that gets the channel, dlog, statistical parameter and random and uses them to
	* create the ZK provers.
	* @param channel
	* @param dlog
	* @param t statistical parameter
	* @param random
	*/
	CmtPedersenWithProofsCommitter(shared_ptr<ChannelServer> channel,
		shared_ptr<DlogGroup> dlog, int t, std::mt19937 random) :
		CmtPedersenCommitter(channel, dlog, random) {
		doConstruct(t);
	};
	void proveKnowledge(long id) override;
	void proveCommittedValue(long id) override;
};

/**
* Concrete implementation of receiver with proofs.
* This implementation uses ZK based on SigmaPedersenKnowledge and SIgmaPedersenCommittedValue.
*/
class CmtPedersenWithProofsReceiver : public CmtPedersenReceiver, public CmtWithProofsReceiver {
private:
	// Verifies that the committer knows the committed value.
	shared_ptr<ZKPOKFromSigmaCmtPedersenVerifier> knowledgeVerifier;
	// Verifies that the committed value is x.
	// Usually, if the commitment scheme is PerfectlyBinding secure, than a ZK is used to verify committed value.
	// In Pedersen, this is not the case since Pedersen is not PerfectlyBinding secure.
	// In order to be able to use the Pedersen scheme we need to verify committed value with ZKPOK instead.
	shared_ptr<ZKPOKFromSigmaCmtPedersenVerifier> committedValVerifier;
	/**
	* Creates the ZK verifiers using sigma protocols that verifies Pedersen's proofs.
	* @param t
	*/
	void doConstruct(int t);
public:
	/**
	* Default constructor that gets the channel and creates the ZK verifiers with default Dlog group.
	* @param channel
	*/
	CmtPedersenWithProofsReceiver(shared_ptr<ChannelServer> channel, int t) : CmtPedersenReceiver(channel) {
		doConstruct(t);
	};

	/**
	* Constructor that gets the channel, dlog, statistical parameter and random and uses them to create the ZK provers.
	* @param channel
	* @param dlog
	* @param t statistical parameter
	* @param random
	*/
	CmtPedersenWithProofsReceiver(shared_ptr<ChannelServer> channel,
		shared_ptr<DlogGroup> dlog, int t, std::mt19937 random) :
		CmtPedersenReceiver(channel, dlog, random) {
		doConstruct(t);
	};

	bool verifyKnowledge(long id) override;

	shared_ptr<CmtCommitValue> verifyCommittedValue(long id) override;
};

/**
* Concrete implementation of committer that executes the Pedersen trapdoor commitment
* scheme in the committer's point of view.<p>
* This commitment is also a trapdoor commitment in the sense that the receiver after
* the commitment phase has a trapdoor value, that if known by the committer would enable
* it to decommit to any value. <p>
* This trapdoor is output by the receiver and can be used by a higher-level application
* (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).<p>
*
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i>
* by Hazay-Lindell.<p>
*
* The pseudo code of this protocol can be found in Protocol 3.3 of pseudo codes document
* at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class CmtPedersenTrapdoorCommitter : public CmtPedersenCommitter {
public:
	/**
	* Constructor that receives a connected channel (to the receiver) and chooses default dlog and random.
	* The receiver needs to be instantiated with the default constructor too.
	* @param channel
	*/
	CmtPedersenTrapdoorCommitter(shared_ptr<ChannelServer> channel) : CmtPedersenCommitter(channel) {};

	/**
	* Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	*/
	CmtPedersenTrapdoorCommitter(shared_ptr<ChannelServer> channel,
		shared_ptr<DlogGroup> dlog, std::mt19937 random) :
		CmtPedersenCommitter(channel, dlog, random) {};

	/**
	* Validate the h value received from the receiver in the pre process phase.
	* @param trap the trapdoor outputed from the receiver's commit phase.
	* @return true, if valid; false, otherwise.
	*/
	bool validate(shared_ptr<CmtRCommitPhaseOutput> trap);
};

/**
* Concrete implementation of receiver that executes the Pedersen trapdoor commitment
* scheme in the receiver's point of view.<p>
* This commitment is also a trapdoor commitment in the sense that the receiver after
* the commitment phase has a trapdoor value, that if known by the committer would enable
* it to decommit to any value. <p>
* This trapdoor is output by the receiver and can be used by a higher-level application
* (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).<p>
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i>
* by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 3.3 of pseudo codes
* document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class CmtPedersenTrapdoorReceiver : public CmtPedersenReceiver {
public:
	/**
	* Constructor that receives a connected channel (to the receiver),
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The committer needs to be instantiated with the same DlogGroup,
	* otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	*/
	CmtPedersenTrapdoorReceiver(shared_ptr<ChannelServer> channel,
		shared_ptr<DlogGroup> dlog, std::mt19937 random) :
		CmtPedersenReceiver(channel, dlog, random) {};

	/**
	* Returns the receiver's trapdoor from the preprocess phase.
	*/
	biginteger getTrapdoor() { return trapdoor; };
	shared_ptr<CmtRCommitPhaseOutput> receiveCommitment() override {
		// get the output from the super.receiverCommiotment.
		auto output = CmtPedersenReceiverCore::receiveCommitment();
		// wrap the output with the trapdoor.
		return make_shared<CmtRTrapdoorCommitPhaseOutput>(trapdoor, output->getCommitmentId());
	};
};


/**
* Concrete implementation of Zero Knowledge prover.<p>
* This is a transformation that takes any Sigma protocol and any perfectly hiding
* trapdoor(equivocal) commitment scheme and yields a zero - knowledge proof of knowledge.<p>
* For more information see Protocol 6.5.4, page 165 of Hazay - Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 2.2 of pseudo codes
* document at{ @link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class ZKPOKFromSigmaCmtPedersenProver : public ZKPOKProver {
public:
	/**
	* Constructor that accepts the underlying channel and sigma protocol's prover.
	* @param channel used for communication
	* @param sProver underlying sigma prover to use.
	*/
	ZKPOKFromSigmaCmtPedersenProver(shared_ptr<ChannelServer> channel,
		shared_ptr<SigmaProverComputation> sProver, shared_ptr<DlogGroup> dg) {
		this->sProver = sProver;
		this->receiver = make_shared<CmtPedersenTrapdoorReceiver>(channel, dg, get_seeded_random());
		this->channel = channel;
	}

	/**
	* Runs the prover side of the Zero Knowledge proof.<p>
	* Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.<p>
	* This function computes the following calculations:<p>
	*
	*		 RUN the receiver in TRAP_COMMIT.commit; let trap be the output<p>
	* 		 COMPUTE the first message a in sigma, using (x,w) as input<p>
	*		 SEND a to V<p>
	*		 RUN the receiver in TRAP_COMMIT.decommit<p>
	*		 IF TRAP_COMMIT.decommit returns some e<p>
	*		      COMPUTE the response z to (a,e) according to sigma<p>
	*		      SEND z and trap to V<p>
	*		      OUTPUT nothing<p>
	*		 ELSE (IF COMMIT.decommit returns INVALID)<p>
	*			  OUTPUT ERROR (CHEAT_ATTEMPT_BY_V)<p>
	*
	* @param input must be an instance of SigmaProverInput.
	*/
	void prove(shared_ptr<ZKProverInput> input);

	/**
	* Processes the second message of the Zero Knowledge protocol.<p>
	* 	"COMPUTE the response z to (a,e) according to sigma<p>
	*   SEND z to V<p>
	*   OUTPUT nothing".<p>
	* This is a blocking function!
	*/
	void processSecondMsg(shared_ptr<byte> e, int eSize, shared_ptr<CmtRCommitPhaseOutput> trap);

private:
	shared_ptr<ChannelServer> channel;
	// underlying prover that computes the proof of the sigma protocol.
	shared_ptr<SigmaProverComputation> sProver;
	shared_ptr<CmtPedersenTrapdoorReceiver> receiver; // underlying Commitment receiver to use.

	/**
	* Runs the receiver in TRAP_COMMIT.commit with P as the receiver.
	*/
	shared_ptr<CmtRCommitPhaseOutput> receiveCommit() {
		return receiver->receiveCommitment();
	};

	/**
	* Processes the first message of the Zero Knowledge protocol:
	*  "COMPUTE the first message a in sigma, using (x,w) as input
	*	SEND a to V".
	* @param input
	*/
	void processFirstMsg(shared_ptr<SigmaProverInput>  input) {
		// compute the first message by the underlying proverComputation.
		auto a = sProver->computeFirstMsg(input);
		auto msg = a->toByteArray();
		int len = a->getSerializedSize();
		// send the first message.
		sendMsgToVerifier(msg.get(), len);
	}

	/**
	* Runs the receiver in TRAP_COMMIT.decommit.
	* If decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	* @param id
	* @param ctOutput
	* @return
	*/
	pair<shared_ptr<byte>, int> receiveDecommit(long id) {
		auto val = receiver->receiveDecommitment(id);
		if (val == NULL) throw CheatAttemptException("Decommit phase returned invalid");
		return receiver->generateBytesFromCommitValue(val);
	};

	/**
	* Sends the given message to the verifier.
	* @param message to send to the verifier.
	*/
	void sendMsgToVerifier(byte* msg, int size) { channel->write_fast(msg, size); };
};


/**
* Concrete implementation of Zero Knowledge verifier.<p>
* This is a transformation that takes any Sigma protocol and any perfectly hiding trapdoor (equivocal)
* commitment scheme and yields a zero-knowledge proof of knowledge.<p>
* For more information see Protocol 6.5.4, page 165 of Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 2.2 of pseudo
* codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class ZKPOKFromSigmaCmtPedersenVerifier : public ZKPOKVerifier {
private:
	shared_ptr<ChannelServer> channel;
	// underlying verifier that computes the proof of the sigma protocol.
	shared_ptr<SigmaVerifierComputation> sVerifier;
	shared_ptr<CmtPedersenTrapdoorCommitter> committer; // underlying Commitment committer to use.
	std::mt19937_64 random;
	shared_ptr<CmtRCommitPhaseOutput> trap;
	/**
	* Runs COMMIT.commit as the committer with input e.
	*/
	long commit(shared_ptr<byte> e, int eSize) {
		auto val = committer->generateCommitValue(e, eSize);
		long id = random();
		id = abs(id);
		committer->commit(val, id);
		return id;
	};
	/**
	* Waits for a message a from the prover.
	* @return the received message
	*/
	void receiveMsgFromProver(shared_ptr<SigmaProtocolMsg> emptyMsg) {
		auto v = channel->read_one();
		emptyMsg->initFromByteVector(v);
	};

	/**
	* Waits for a trapdoor a from the prover.
	*/
	void receiveTrapFromProver(shared_ptr<CmtRCommitPhaseOutput> emptyOutput) {
		auto v = channel->read_one();
		emptyOutput->initFromByteVector(v);
	}
	/**
	* Verifies the proof.
	* @param input
	* @param a first message from prover.
	* @param z second message from prover.
	*/
	bool proccessVerify(shared_ptr<SigmaCommonInput> input,
		shared_ptr<SigmaProtocolMsg> a, shared_ptr<SigmaProtocolMsg> z) {
		// run transcript (a, e, z) is accepting in sigma on input x
		return sVerifier->verify(input, a, z);
	};

public:
	/**
	* Constructor that accepts the underlying channel and sigma protocol's verifier.
	* @param channel used for communication
	* @param sVerifier underlying sigma verifier to use.
	* @param random
	*/
	ZKPOKFromSigmaCmtPedersenVerifier(shared_ptr<ChannelServer> channel,
		shared_ptr<SigmaVerifierComputation> sVerifier, std::mt19937_64 random,
		shared_ptr<CmtRCommitPhaseOutput> emptyTrap, shared_ptr<DlogGroup> dg) {
		this->channel = channel;
		this->sVerifier = sVerifier; 
		this->committer = make_shared<CmtPedersenTrapdoorCommitter>(channel, dg, get_seeded_random());
		this->random = random;
		this->trap = emptyTrap;
	};

	/**
	* Runs the verifier side of the Zero Knowledge proof.<p>
	* Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.<p>
	* This function computes the following calculations:<p>
	*
	*		 SAMPLE a random challenge  e <- {0, 1^t <p>
	*		 RUN TRAP_COMMIT.commit as the committer with input e<p>
	*		 WAIT for a message a from P<p>
	*		 RUN TRAP_COMMIT.decommit as the decommitter<p>
	*		 WAIT for a message (z,trap) from P<p>
	*		 IF  <p>
	*				TRAP_COMMIT.valid(T,trap) = 1, where T  is the transcript from the commit phase, AND<p>
	*				Transcript (a, e, z) is accepting in sigma on input x<p>
	*          OUTPUT ACC<p>
	*       ELSE 	<p>
	*          OUTPUT REJ<p>

	* @param input must be an instance of SigmaCommonInput.
	*/
	bool verify(shared_ptr<ZKCommonInput> input, shared_ptr<SigmaProtocolMsg> emptyA, 
		shared_ptr<SigmaProtocolMsg> emptyZ) override;

};

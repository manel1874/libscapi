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


#include "../../include/interactive_mid_protocols/ZeroKnowledge.hpp"


/************************************************/
/*   ZKFromSigmaProver                          */
/************************************************/

ZKFromSigmaProver::ZKFromSigmaProver(shared_ptr<CommParty> channel,
	shared_ptr<SigmaProverComputation> sProver, shared_ptr<CmtReceiver> receiver) {
	// receiver must be an instance of PerfectlyHidingCT
	auto perfectHidingReceiver = dynamic_pointer_cast<PerfectlyHidingCmt>(receiver);
	if (!perfectHidingReceiver) 
		throw SecurityLevelException("the given CTReceiver must be an instance of PerfectlyHidingCmt");
	// receiver must be a commitment scheme on ByteArray or on BigInteger
	auto onBigIntegerReceiver = dynamic_pointer_cast<CmtOnBigInteger>(receiver);
	auto onByteArrayReceiver = dynamic_pointer_cast<CmtOnByteArray>(receiver);
	if (!onBigIntegerReceiver && !onByteArrayReceiver) 
		throw invalid_argument("the given receiver must be a commitment scheme on ByteArray or on BigInteger");

	this->sProver = sProver;
	this->receiver = receiver;
	this->channel = channel;
}

void ZKFromSigmaProver::prove(shared_ptr<ZKProverInput> input) {
	// the given input must be an instance of SigmaProtocolInput.
	auto sigmaProverInput = std::dynamic_pointer_cast<SigmaProverInput>(input);
	if (!sigmaProverInput) 
		throw invalid_argument("the given input must be an instance of SigmaProverInput");

	// run the receiver in COMMIT.commit 
	auto output = receiveCommit();
	// compute the first message a in sigma, using (x,w) as input and 
	// send a to V
	processFirstMsg(sigmaProverInput);
	// run the receiver in COMMIT.decommit 
	// if decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	auto e = receiveDecommit(output->getCommitmentId());
	// IF decommit returns some e, compute the response z to (a,e) according to sigma, 
	// Send z to V and output nothing
	processSecondMsg(e.data(), e.size());
}

/************************************************/
/*   ZKFromSigmaVerifier                        */
/************************************************/

ZKFromSigmaVerifier::ZKFromSigmaVerifier(shared_ptr<CommParty> channel,
	shared_ptr<SigmaVerifierComputation> sVerifier, shared_ptr<CmtCommitter> committer) {
	// committer must be an instance of PerfectlyHidingCT
	auto perfectHidingCommiter = std::dynamic_pointer_cast<PerfectlyHidingCmt>(committer);
	if (!perfectHidingCommiter) 
		throw SecurityLevelException("the given CTCommitter must be an instance of PerfectlyHidingCmt");
	
	// receiver must be a commitment scheme on ByteArray or on BigInteger
	auto onBigIntegerCommitter = std::dynamic_pointer_cast<CmtOnBigInteger>(committer);
	auto onByteArrayCommitter = std::dynamic_pointer_cast<CmtOnByteArray>(committer);
	if (!onBigIntegerCommitter && !onByteArrayCommitter) 
		throw invalid_argument("the given committer must be a commitment scheme on ByteArray or on BigInteger");

	this->sVerifier = sVerifier;
	this->committer = committer;
	this->channel = channel;
	this->random = get_seeded_random64();
}

bool ZKFromSigmaVerifier::verify(ZKCommonInput* input, SigmaProtocolMsg* emptyA, SigmaProtocolMsg* emptyZ) {
	// the given input must be an instance of SigmaProtocolInput.
	auto sigmaCommonInput = dynamic_cast<SigmaCommonInput*>(input);
	if (!sigmaCommonInput)
		throw invalid_argument("the given input must be an instance of SigmaCommonInput");

	// sample a random challenge  e <- {0, 1}^t 
	sVerifier->sampleChallenge();
	auto e = sVerifier->getChallenge();
	// run COMMIT.commit as the committer with input e
	long id = commit(e);
	// wait for a message a from P
	receiveMsgFromProver(emptyA);
	// run COMMIT.decommit as the decommitter
	decommit(id);
	// wait for a message z from P, 
	// if transcript (a, e, z) is accepting in sigma on input x, output ACC
	// else outupt REJ
	return proccessVerify(sigmaCommonInput, emptyA, emptyZ);
}

void ZKFromSigmaVerifier::receiveMsgFromProver(SigmaProtocolMsg* concreteMsg) {
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	concreteMsg->initFromByteVector(rawMsg);
}

/************************************************/
/*   ZKPOKFromSigmaCmtPedersenProver            */
/************************************************/

void ZKPOKFromSigmaCmtPedersenProver::prove(shared_ptr<ZKProverInput> input) {
	// the given input must be an instance of SigmaProverInput.
	auto sigmaProverInput = dynamic_pointer_cast<SigmaProverInput>(input);
	if (!sigmaProverInput)
		throw invalid_argument("the given input must be an instance of SigmaProverInput");

	// run the receiver in TRAP_COMMIT.commit 
	auto trap = receiveCommit();
	auto trapR = dynamic_pointer_cast<CmtRTrapdoorCommitPhaseOutput>(trap);
	// compute the first message a in sigma, using (x,w) as input and 
	// send a to V
	processFirstMsg(sigmaProverInput);
	// run the receiver in TRAP_COMMIT.decommit 
	// if decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	auto e = receiveDecommit(trap->getCommitmentId());
	// if decommit returns some e, compute the response z to (a,e) according to sigma, 
	// send z to V and output nothing
	processSecondMsg(e, trap);

}

void ZKPOKFromSigmaCmtPedersenProver::processSecondMsg(vector<byte> e, shared_ptr<CmtRCommitPhaseOutput> trap) { 
	// compute the second message by the underlying proverComputation.
	auto z = sProver->computeSecondMsg(e);

	// send the second message.
	auto raw_z = z->toString();
	sendMsgToVerifier(raw_z);

	// send the trap.
	auto raw_trap = trap->toString();
	sendMsgToVerifier(raw_trap);
}



/************************************************/
/*   ZKPOKFromSigmaCmtPedersenVerifier          */
/************************************************/
bool ZKPOKFromSigmaCmtPedersenVerifier::verify(ZKCommonInput* input, 
	SigmaProtocolMsg* emptyA, SigmaProtocolMsg* emptyZ) {
	// the given input must be an instance of SigmaProtocolInput.
	auto sigmaCommonInput = dynamic_cast<SigmaCommonInput*>(input);
	if (!sigmaCommonInput) 
		throw invalid_argument("the given input must be an instance of SigmaCommonInput");

	// sample a random challenge  e <- {0, 1}^t 
	sVerifier->sampleChallenge();
	auto e = sVerifier->getChallenge();

	// run TRAP_COMMIT.commit as the committer with input e,
	long id = commit(e);
	// wait for a message a from P
	receiveMsgFromProver(emptyA);
	// run COMMIT.decommit as the decommitter
	committer->decommit(id);

	bool valid = true;

	// wait for a message z from P
	receiveMsgFromProver(emptyZ);
	// wait for trap from P
	receiveTrapFromProver(trap.get());

	// run TRAP_COMMIT.valid(T,trap), where T is the transcript from the commit phase
	valid = valid && committer->validate(trap);

	// run transcript (a, e, z) is accepting in sigma on input x
	valid = valid && sVerifier->verify(sigmaCommonInput, emptyA, emptyZ);
	

	// if decommit and sigma verify returned true, return ACCEPT. Else, return REJECT.
	return valid;
}

/**
* Runs COMMIT.commit as the committer with input e.
*/
long ZKPOKFromSigmaCmtPedersenVerifier::commit(vector<byte> e) {
	auto val = committer->generateCommitValue(e);
	long id = random();
	id = abs(id);
	committer->commit(val, id);
	return id;
};
/**
* Waits for a message a from the prover.
* @return the received message
*/
void ZKPOKFromSigmaCmtPedersenVerifier::receiveMsgFromProver(SigmaProtocolMsg* emptyMsg) {
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	emptyMsg->initFromByteVector(rawMsg);
};

/**
* Waits for a trapdoor a from the prover.
*/
void ZKPOKFromSigmaCmtPedersenVerifier::receiveTrapFromProver(CmtRCommitPhaseOutput* emptyOutput) {
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	emptyOutput->initFromByteVector(rawMsg);
}


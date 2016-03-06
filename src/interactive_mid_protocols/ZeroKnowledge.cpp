#include "../../include/interactive_mid_protocols/ZeroKnowledge.hpp"


/************************************************/
/*   ZKFromSigmaProver                          */
/************************************************/

ZKFromSigmaProver::ZKFromSigmaProver(shared_ptr<ChannelServer> channel,
	shared_ptr<SigmaProverComputation> sProver, shared_ptr<CmtReceiver> receiver) {
	// receiver must be an instance of PerfectlyHidingCT
	auto perfectHidingReceiver = std::dynamic_pointer_cast<PerfectlyHidingCmt>(receiver);
	if (!perfectHidingReceiver) 
		throw SecurityLevelException("the given CTReceiver must be an instance of PerfectlyHidingCmt");
	// receiver must be a commitment scheme on ByteArray or on BigInteger
	auto onBigIntegerReceiver = std::dynamic_pointer_cast<CmtOnBigInteger>(receiver);
	auto onByteArrayReceiver = std::dynamic_pointer_cast<CmtOnByteArray>(receiver);
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
	auto ePair = receiveDecommit(output->getCommitmentId());
	// IF decommit returns some e, compute the response z to (a,e) according to sigma, 
	// Send z to V and output nothing
	processSecondMsg(ePair.first.get(), ePair.second);
}

/************************************************/
/*   ZKFromSigmaVerifier                        */
/************************************************/

ZKFromSigmaVerifier::ZKFromSigmaVerifier(shared_ptr<ChannelServer> channel,
	shared_ptr<SigmaVerifierComputation> sVerifier, shared_ptr<CmtCommitter> committer,
	std::mt19937_64 random) {
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
	this->random = random;
}

bool ZKFromSigmaVerifier::verify(shared_ptr<ZKCommonInput> input, 
	shared_ptr<SigmaProtocolMsg> emptyA, shared_ptr<SigmaProtocolMsg> emptyZ) {
	// the given input must be an instance of SigmaProtocolInput.
	auto sigmaCommonInput = std::dynamic_pointer_cast<SigmaCommonInput>(input);
	if (!sigmaCommonInput)
		throw invalid_argument("the given input must be an instance of SigmaCommonInput");

	// sample a random challenge  e <- {0, 1}^t 
	sVerifier->sampleChallenge();
	auto ePair = sVerifier->getChallenge();
	// run COMMIT.commit as the committer with input e
	long id = commit(ePair.first, ePair.second);
	// wait for a message a from P
	receiveMsgFromProver(emptyA);
	// run COMMIT.decommit as the decommitter
	decommit(id);
	// wait for a message z from P, 
	// if transcript (a, e, z) is accepting in sigma on input x, output ACC
	// else outupt REJ
	return proccessVerify(sigmaCommonInput, emptyA, emptyZ);
}

void ZKFromSigmaVerifier::receiveMsgFromProver(shared_ptr<SigmaProtocolMsg> concreteMsg) {
	auto raw_msg = channel->read_one();
	concreteMsg->initFromByteVector(raw_msg);
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
	auto ePair = receiveDecommit(trap->getCommitmentId());
	// if decommit returns some e, compute the response z to (a,e) according to sigma, 
	// send z to V and output nothing
	processSecondMsg(ePair.first, ePair.second, trap);

}

void ZKPOKFromSigmaCmtPedersenProver::processSecondMsg(shared_ptr<byte> e, int eSize, 
	shared_ptr<CmtRCommitPhaseOutput> trap) { 
	// compute the second message by the underlying proverComputation.
	auto z = sProver->computeSecondMsg(e.get(), eSize);

	// send the second message.
	auto raw_z = z->toByteArray();
	int raw_z_size = z->getSerializedSize();
	sendMsgToVerifier(raw_z.get(), raw_z_size);

	// send the trap.
	auto raw_trap = trap->toByteArray();
	int raw_trap_size = trap->getSerializedSize();
	sendMsgToVerifier(raw_trap.get(), raw_trap_size);
}



/************************************************/
/*   ZKPOKFromSigmaCmtPedersenVerifier          */
/************************************************/
bool ZKPOKFromSigmaCmtPedersenVerifier::verify(shared_ptr<ZKCommonInput> input, 
	shared_ptr<SigmaProtocolMsg> emptyA, shared_ptr<SigmaProtocolMsg> emptyZ) {
	// the given input must be an instance of SigmaProtocolInput.
	auto sigmaCommonInput = dynamic_pointer_cast<SigmaCommonInput>(input);
	if (!sigmaCommonInput) 
		throw invalid_argument("the given input must be an instance of SigmaCommonInput");

	// sample a random challenge  e <- {0, 1}^t 
	sVerifier->sampleChallenge();
	auto ePair = sVerifier->getChallenge();

	// run TRAP_COMMIT.commit as the committer with input e,
	long id = commit(ePair.first, ePair.second);
	// wait for a message a from P
	receiveMsgFromProver(emptyA);
	// run COMMIT.decommit as the decommitter
	committer->decommit(id);

	bool valid = true;

	// wait for a message z from P
	receiveMsgFromProver(emptyZ);
	// wait for trap from P
	receiveTrapFromProver(trap);

	// run TRAP_COMMIT.valid(T,trap), where T is the transcript from the commit phase
	valid = valid && committer->validate(trap);

	// run transcript (a, e, z) is accepting in sigma on input x
	valid = valid && proccessVerify(sigmaCommonInput, emptyA, emptyZ);

	// if decommit and sigma verify returned true, return ACCEPT. Else, return REJECT.
	return valid;
}

/********************************************/
/*   CmtPedersenWithProofsCommitter         */
/********************************************/
void CmtPedersenWithProofsCommitter::doConstruct(int t) {
	//SigmaProverComputation pedersenCommittedValProver = new SigmaPedersenCommittedValueProverComputation(dlog, t, random);
	//SigmaProverComputation pedersenCTKnowledgeProver = new SigmaPedersenCmtKnowledgeProverComputation(dlog, t, random);
	//knowledgeProver = make_shared<ZKPOKFromSigmaCmtPedersenProver>(channel, pedersenCTKnowledgeProver);
	//committedValProver = make_shared<ZKPOKFromSigmaCmtPedersenProver>(channel, pedersenCommittedValProver);
}

/********************************************/
/*   CmtPedersenTrapdoorCommitter           */
/********************************************/
bool CmtPedersenTrapdoorCommitter::validate(shared_ptr<CmtRCommitPhaseOutput> trap) {
	auto trapdoor = dynamic_pointer_cast<CmtRTrapdoorCommitPhaseOutput>(trap);
	if (!trapdoor)
		throw invalid_argument("the given trapdor should be an instance of CmtRTrapdoorCommitPhaseOutput");
	// check that g^trapdoor equals to h.
	auto gToTrap = dlog->exponentiate(dlog->getGenerator(), trapdoor->getTrap());
	return (*gToTrap == *h); 
}
#include "../../include/interactive_mid_protocols/SigmaProtocol.hpp"

/***************************/
/*   SigmaProver           */
/***************************/

void SigmaProver::processFirstMsg(shared_ptr<SigmaProverInput> input) {
	// compute the first message by the underlying proverComputation.
	auto a = proverComputation->computeFirstMsg(input);
	// send the first message.
	sendMsgToVerifier(a);
	// save the state of this protocol.
	doneFirstMsg = true;
}

void SigmaProver::processSecondMsg() {
	if (!doneFirstMsg)
		throw IllegalStateException("processFirstMsg should be called before processSecondMsg");
	// receive the challenge.
	auto v = channel->read_one();

	// compute the second message by the underlying proverComputation.
	auto z = proverComputation->computeSecondMsg(&(v->at(0)), v->size());

	// send the second message.
	sendMsgToVerifier(z);

	// save the state of this sigma protocol.
	doneFirstMsg = false;
	delete v; // alraedy decoded and used at this stage
}


/***************************/
/*   SigmaVerifier         */
/***************************/
bool SigmaVerifier::verify(shared_ptr<SigmaCommonInput> input) {
	// samples the challenge.
	sampleChallenge();
	// sends the challenge.
	sendChallenge();
	// serifies the proof.
	return processVerify(input);
}

void SigmaVerifier::sendChallenge() {

	// wait for first message from the prover.
	receiveMsgFromProver(a);

	// get the challenge from the verifierComputation.
	auto challengePair = verifierComputation->getChallenge();
	if (challengePair.second == 0)
		throw IllegalStateException("challenge_size=0. Make sure that sampleChallenge function is called before sendChallenge");
	
	// send the challenge.
	sendChallengeToProver(challengePair.first.get(), challengePair.second);

	// save the state of the protocol.
	doneChallenge = true;
}

bool SigmaVerifier::processVerify(shared_ptr<SigmaCommonInput> input) {
	if (!doneChallenge)
		throw IllegalStateException("sampleChallenge and sendChallenge should be called before processVerify");
	// wait for second message from the prover.
	receiveMsgFromProver(z);
	// verify the proof
	bool verified = verifierComputation->verify(input, a, z);
	// save the state of the protocol.
	doneChallenge = false;
	return verified;
}

void SigmaVerifier::receiveMsgFromProver(shared_ptr<SigmaProtocolMsg> msg) {
	auto v = channel->read_one();
	msg->initFromByteVector(v);
}
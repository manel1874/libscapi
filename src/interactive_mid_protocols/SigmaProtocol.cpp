#include "../../include/interactive_mid_protocols/SigmaProtocol.hpp"

/***************************/
/*   SigmaProtocolProver   */
/***************************/

void SigmaProtocolProver::processFirstMsg(shared_ptr<SigmaProverInput> input) {
	// compute the first message by the underlying proverComputation.
	auto a = proverComputation->computeFirstMsg(input);
	// send the first message.
	sendMsgToVerifier(a.get());
	// save the state of this protocol.
	doneFirstMsg = true;
}

void SigmaProtocolProver::processSecondMsg() {
	if (!doneFirstMsg)
		throw IllegalStateException("processFirstMsg should be called before processSecondMsg");
	// receive the challenge.
	auto v = channel->read_one();

	// compute the second message by the underlying proverComputation.
	auto z = proverComputation->computeSecondMsg(*v);

	// send the second message.
	sendMsgToVerifier(z.get());

	// save the state of this sigma protocol.
	doneFirstMsg = false;
	delete v; // alraedy decoded and used at this stage
}


/***************************/
/*   SigmaProtocolVerifier */
/***************************/
bool SigmaProtocolVerifier::verify(SigmaCommonInput* input) {
	// samples the challenge.
	sampleChallenge();
	// sends the challenge.
	sendChallenge();
	// serifies the proof.
	return processVerify(input);
}

void SigmaProtocolVerifier::sendChallenge() {

	// wait for first message from the prover.
	receiveMsgFromProver(a.get());

	// get the challenge from the verifierComputation.
	auto challenge = verifierComputation->getChallenge();
	if (challenge.size() == 0)
		throw IllegalStateException("challenge_size=0. Make sure that sampleChallenge function is called before sendChallenge");
	
	// send the challenge.
	sendChallengeToProver(challenge);

	// save the state of the protocol.
	doneChallenge = true;
}

bool SigmaProtocolVerifier::processVerify(SigmaCommonInput* input) {
	if (!doneChallenge)
		throw IllegalStateException("sampleChallenge and sendChallenge should be called before processVerify");
	// wait for second message from the prover.
	receiveMsgFromProver(z.get());
	// verify the proof
	bool verified = verifierComputation->verify(input, a.get(), z.get());
	// save the state of the protocol.
	doneChallenge = false;
	return verified;
}

void SigmaProtocolVerifier::receiveMsgFromProver(SigmaProtocolMsg* msg) {
	auto v = channel->read_one();
	msg->initFromByteVector(*v);
}
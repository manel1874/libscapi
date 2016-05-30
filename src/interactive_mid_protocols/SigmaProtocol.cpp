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
	int challengeSize = channel->readSize();
	cout << "Got challenge. size: " << challengeSize << endl;
	vector<byte> challenge(challengeSize); // will be deleted by the end of the scope with all its content
	channel->read(&challenge[0], challengeSize);

	// compute the second message by the underlying proverComputation.
	auto z = proverComputation->computeSecondMsg(challenge);

	// send the second message.
	sendMsgToVerifier(z.get());

	// save the state of this sigma protocol.
	doneFirstMsg = false;
}


/***************************/
/*   SigmaProtocolVerifier */
/***************************/
bool SigmaProtocolVerifier::verify(SigmaCommonInput* input) {
	// samples the challenge.
	sampleChallenge();
	cout << "challenge sampled, size of challenge: " << this->getChallenge().size() << ". sending it." << endl;
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
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	msg->initFromByteVector(rawMsg);
}

void SigmaMultipleMsg::initFromString(const string & s) {
	auto str_vec = explode(s, ':');
	int len = str_vec.size();
	for (int i = 0; i < len; i++) {
		messages[i]->initFromString(str_vec[i]);
	}
}

string SigmaMultipleMsg::toString() {
	string output;
	for (auto message : messages) {
		output += message->toString();
	}
	return output;
}
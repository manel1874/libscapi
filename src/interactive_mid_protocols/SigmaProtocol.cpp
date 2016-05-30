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
		output += ":";
	}
	return output;
}

/***************************************/
/*   SigmaANDProverInput               */
/***************************************/
shared_ptr<SigmaCommonInput> SigmaMultipleProverInput::getCommonInput() {
	/*
	* There are two options to implement this function:
	* 1. Create a new instance of SigmaANDCommonInput every time the function is called.
	* 2. Create the object in the construction time and return it every time this function is called.
	* This class holds an array of SigmaProverInput, where each instance in the array holds
	* an instance of SigmaCommonParams inside it.
	* In the second option above, this class will have in addition an array of SigmaCommonInput.
	* This way, the SigmaCommonInput instances will appear twice -
	* once in the array and once in the corresponding SigmaProverInput.
	* This is an undesired duplication and redundancy, So we decided to implement using the
	* first way, although this is less efficient.
	* In case the efficiency is important, a user can derive this class and override this implementation.
	*/
	vector<shared_ptr<SigmaCommonInput>> paramsArr;
	for (auto sigmaInput : sigmaInputs)
		paramsArr.push_back(sigmaInput->getCommonInput());

	return make_shared<SigmaMultipleCommonInput>(paramsArr);
}
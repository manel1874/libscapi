#include "../../include/interactive_mid_protocols/SigmaProtocolAnd.hpp"


/***************************************/
/*   SigmaANDProverComputation         */
/***************************************/

SigmaANDProverComputation::SigmaANDProverComputation(vector<shared_ptr<SigmaProverComputation>> provers, int t) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for (auto prover : provers)
		if(t != prover->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying provers objects.");

	this->provers = provers;
	len = provers.size();
	this->t = t;
}

shared_ptr<SigmaProtocolMsg> SigmaANDProverComputation::computeFirstMsg(shared_ptr<SigmaProverInput> in) {
	// checks that the input is as expected.
	auto input = checkInput(in.get());
	auto proversInput = input->getInputs();

	// create an array to hold all messages.
	vector<shared_ptr<SigmaProtocolMsg>> firstMessages;

	// compute all first messages and add them to the array list.
	for (int i = 0; i < len; i++) 
		firstMessages.push_back(provers[i]->computeFirstMsg(proversInput[i]));

	// create a SigmaMultipleMsg with the messages array.
	return make_shared<SigmaMultipleMsg>(firstMessages);
}

shared_ptr<SigmaProtocolMsg> SigmaANDProverComputation::computeSecondMsg(
	vector<byte> challenge) {
	// create an array to hold all messages.
	vector<shared_ptr<SigmaProtocolMsg>> secondMessages;
	// compute all second messages and add them to the array list.
	for (auto prover : provers) {
		secondMessages.push_back(prover->computeSecondMsg(challenge));
	}

	// Create a SigmaMultipleMsg with the messages array.
	return make_shared<SigmaMultipleMsg>(secondMessages);
}

shared_ptr<SigmaSimulator> SigmaANDProverComputation::getSimulator() {
	vector<shared_ptr<SigmaSimulator>> simulators;
	for(auto prover:provers)
		simulators.push_back(prover->getSimulator());
	return make_shared<SigmaANDSimulator>(simulators, t);
}

SigmaMultipleProverInput* SigmaANDProverComputation::checkInput(SigmaProverInput* in) {
	auto input = dynamic_cast<SigmaMultipleProverInput*>(in);
	if (!input)
		throw invalid_argument("the given input must be an instance of SigmaMultipleProverInput");

	int inputLen = input->getInputs().size();

	// if number of inputs is not equal to number of provers, throw exception.
	if (inputLen != len)
		throw invalid_argument("number of inputs is different from number of underlying provers.");
	return input;
}

/***************************************/
/*   SigmaANDSimulator                 */
/***************************************/

SigmaANDSimulator::SigmaANDSimulator(vector<shared_ptr<SigmaSimulator>> simulators, int t) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for(auto sigmaSimulator : simulators)
		if(t!=sigmaSimulator->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying simulators objects.");

	this->simulators = simulators;
	len = simulators.size();
	this->t = t;
	this->random = get_seeded_random();
}

shared_ptr<SigmaSimulatorOutput> SigmaANDSimulator::simulate(SigmaCommonInput* input,
	vector<byte> challenge) {
	if (!checkChallengeLength(challenge.size())) 
		throw CheatAttemptException("the length of the given challenge is different from the soundness parameter");
	
	auto andInput = dynamic_cast<SigmaMultipleCommonInput*>(input);
	if (andInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaANDCommonInput");
	}
	
	vector<shared_ptr<SigmaCommonInput>> simulatorsInput = andInput->getInputs();
	int inputLen = simulatorsInput.size();

	// if number of inputs is not equal to number of provers, throw exception.
	if (inputLen != len) 
		throw invalid_argument("number of inputs is different from number of underlying simulators.");

	vector<shared_ptr<SigmaProtocolMsg>> aOutputs;
	vector<shared_ptr<SigmaProtocolMsg>> zOutputs;
	shared_ptr<SigmaSimulatorOutput> output = NULL;
	// run each Sigma protocol simulator with the given challenge.
	for (int i = 0; i < len; i++) {
		output = simulators[i]->simulate(simulatorsInput[i].get(), challenge);
		aOutputs.push_back(output->getA());
		zOutputs.push_back(output->getZ());
	}

	// create a SigmaMultipleMsg from the simulates function's outputs to create a and z.
	auto a = make_shared<SigmaMultipleMsg>(aOutputs);
	auto z = make_shared<SigmaMultipleMsg>(zOutputs);

	// output (a,e,eSize,z).
	return make_shared<SigmaSimulatorOutput>(a, challenge, z);
}

shared_ptr<SigmaSimulatorOutput> SigmaANDSimulator::simulate(SigmaCommonInput* input) {
	//Create a new byte array of size t/8, to get the required byte size and fill it with random values.
	vector<byte> e(t / 8);
	RAND_bytes(e.data(), t / 8);
	//modify the challenge to be positive.
	e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;
	// call the other simulate function with the given input and the samples e.
	return simulate(input, e);
}


/***************************************/
/*   SigmaANDVerifierComputation       */
/***************************************/
SigmaANDVerifierComputation::SigmaANDVerifierComputation(vector<shared_ptr<SigmaVerifierComputation>> verifiers, int t) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for(auto verifier : verifiers)
		if(t != verifier->getSoundnessParam())
			throw new invalid_argument("the given t does not equal to one of the t values in the underlying verifiers objects.");

	this->verifiers = verifiers;
	len = verifiers.size();
	this->t = t;
	this->random = get_seeded_random();
}

void SigmaANDVerifierComputation::sampleChallenge() {
	//make space for t/8 bytes and fill it with random values.
	e.resize(t / 8);
	RAND_bytes(e.data(), t / 8);
	//modify the challenge to be positive.
	e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;
	
	// set all the other verifiers with the sampled challenge.
	for (auto verifier : verifiers)
		verifier->setChallenge(e);
}

void SigmaANDVerifierComputation::setChallenge(vector<byte> challenge) {
	e = challenge;
	for (auto verifier : verifiers)
		verifier->setChallenge(challenge);
}

bool SigmaANDVerifierComputation::verify(SigmaCommonInput* input, 
	SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	// checks that the input is as expected.
	auto in = dynamic_cast<SigmaMultipleCommonInput*>(input);
	int inputLen = in->getInputs().size();

	// if number of inputs is not equal to number of verifiers, throw exception.
	if (inputLen != len) {
		throw invalid_argument("number of inputs is different from number of underlying verifiers.");
	}
	auto verifiersInput = in->getInputs();

	bool verified = true;

	// if one of the messages is illegal, throw exception.
	SigmaMultipleMsg *first = dynamic_cast<SigmaMultipleMsg*>(a);
	SigmaMultipleMsg *second = dynamic_cast<SigmaMultipleMsg*>(z);
	if (first == NULL)
		throw invalid_argument("first message must be an instance of SigmaMultipleMsg");
	if (second == NULL)
		throw invalid_argument("second message must be an instance of SigmaMultipleMsg");

	auto firstMessages  = first ->getMessages();
	auto secondMessages = second->getMessages();

	//Compute all verifier checks.
	for (int i = 0; i < len; i++) 
		verified = verified && verifiers[i]->verify(verifiersInput[i].get(), firstMessages[i].get(), secondMessages[i].get());

	// return true if all verifiers returned true; false, otherwise.
	return verified;
}


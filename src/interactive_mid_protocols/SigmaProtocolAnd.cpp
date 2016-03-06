#include "../../include/interactive_mid_protocols/SigmaProtocolAnd.hpp"


/***************************************/
/*   SigmaANDProverInput               */
/***************************************/
shared_ptr<SigmaCommonInput> SigmaANDProverInput::getCommonParams() {
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
	for(auto sigmaInput : sigmaInputs)
		paramsArr.push_back(sigmaInput->getCommonParams());

	return make_shared<SigmaANDCommonInput>(paramsArr);
}

/***************************************/
/*   SigmaANDProverComputation         */
/***************************************/

SigmaANDProverComputation::SigmaANDProverComputation(
	vector<shared_ptr<SigmaProverComputation>> provers, int t, mt19937 random) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for (auto prover : provers)
		if(t != prover->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying provers objects.");

	this->provers = provers;
	len = provers.size();
	this->t = t;
	this->random = random;
}

shared_ptr<SigmaProtocolMsg> SigmaANDProverComputation::computeFirstMsg(shared_ptr<SigmaProverInput> in) {
	// checks that the input is as expected.
	auto input = checkInput(in);
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
	byte* challenge, int challenge_size) {
	// create an array to hold all messages.
	vector<shared_ptr<SigmaProtocolMsg>> secondMessages;
	// compute all second messages and add them to the array list.
	for(auto prover : provers)
		secondMessages.push_back(prover->computeSecondMsg(challenge, challenge_size));

	// Create a SigmaMultipleMsg with the messages array.
	return make_shared<SigmaMultipleMsg>(secondMessages);
}

shared_ptr<SigmaSimulator> SigmaANDProverComputation::getSimulator() {
	vector<shared_ptr<SigmaSimulator>> simulators;
	for(auto prover:provers)
		simulators.push_back(prover->getSimulator());
	return make_shared<SigmaANDSimulator>(simulators, t, random);
}

shared_ptr<SigmaANDProverInput> SigmaANDProverComputation::checkInput(shared_ptr<SigmaProverInput> in) {
	SigmaANDProverInput *input = dynamic_cast<SigmaANDProverInput*>(in.get());
	if (!input)
		throw invalid_argument("the given input must be an instance of SigmaANDProverInput");

	int inputLen = input->getInputs().size();

	// if number of inputs is not equal to number of provers, throw exception.
	if (inputLen != len)
		throw invalid_argument("number of inputs is different from number of underlying provers.");
	shared_ptr<SigmaANDProverInput> sharedI(input);
	return sharedI;
}

/***************************************/
/*   SigmaANDSimulator                 */
/***************************************/

SigmaANDSimulator::SigmaANDSimulator(vector<shared_ptr<SigmaSimulator>> simulators, 
	int t, mt19937 random) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for(auto sigmaSimulator : simulators)
		if(t!=sigmaSimulator->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying simulators objects.");

	this->simulators = simulators;
	len = simulators.size();
	this->t = t;
	this->random = random;
}

shared_ptr<SigmaSimulatorOutput> SigmaANDSimulator::simulate(shared_ptr<SigmaCommonInput> input,
	shared_ptr<byte> challenge, int challenge_size) {
	if (!checkChallengeLength(challenge_size)) 
		throw CheatAttemptException("the length of the given challenge is different from the soundness parameter");
	
	SigmaANDCommonInput *andInput = (SigmaANDCommonInput *)input.get();

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
		output = simulators[i]->simulate(simulatorsInput[i], challenge, challenge_size);
		aOutputs.push_back(output->getA());
		zOutputs.push_back(output->getZ());
	}

	// create a SigmaMultipleMsg from the simulates function's outputs to create a and z.
	auto a = make_shared<SigmaMultipleMsg>(aOutputs);
	auto z = make_shared<SigmaMultipleMsg>(zOutputs);

	// output (a,e,eSize,z).
	return make_shared<SigmaANDSimulatorOutput>(a, challenge, challenge_size, z);
}

shared_ptr<SigmaSimulatorOutput> SigmaANDSimulator::simulate(shared_ptr<SigmaCommonInput> input) {
	// create a new byte array of size t/8, to get the required byte size.
	std::shared_ptr<byte> e(new byte[t/ 8], std::default_delete<byte[]>());
	// fill the byte array with random values.
	if (!RAND_bytes(e.get(), t / 8 ))
		throw runtime_error("key generation failed");
	// call the other simulate function with the given input and the samples e.
	return simulate(input, e, t / 8);
}


/***************************************/
/*   SigmaANDVerifierComputation       */
/***************************************/
SigmaANDVerifierComputation::SigmaANDVerifierComputation(
	vector<shared_ptr<SigmaVerifierComputation>> & verifiers, int t, std::mt19937 random) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for(auto verifier : verifiers)
		if(t != verifier->getSoundnessParam())
			throw new invalid_argument("the given t does not equal to one of the t values in the underlying verifiers objects.");

	this->verifiers = verifiers;
	len = verifiers.size();
	this->t = t;
	this->random = random;
}

void SigmaANDVerifierComputation::sampleChallenge() {
	// create a new byte array of size t/8, to get the required byte size.
	std::shared_ptr<byte> e(new byte[t/8], std::default_delete<byte[]>());
	// fill the byte array with random values.
	if (!RAND_bytes(e.get(), t / 8))
		throw runtime_error("key generation failed");

	// set all the other verifiers with the sampled challenge.
	for (auto verifier : verifiers)
		verifier->setChallenge(e, t / 8);
}

bool SigmaANDVerifierComputation::verify(shared_ptr<SigmaCommonInput> input, 
	shared_ptr<SigmaProtocolMsg> a, shared_ptr<SigmaProtocolMsg> z) {
	// checks that the input is as expected.
	checkInput(input);
	auto verifiersInput = ((SigmaANDCommonInput *)input.get())->getInputs();

	bool verified = true;

	// if one of the messages is illegal, throw exception.
	SigmaMultipleMsg *first = dynamic_cast<SigmaMultipleMsg*>(a.get());
	SigmaMultipleMsg *second = dynamic_cast<SigmaMultipleMsg*>(z.get());
	if (!a)
		throw invalid_argument("first message must be an instance of SigmaMultipleMsg");
	if (!z)
		throw invalid_argument("second message must be an instance of SigmaMultipleMsg");

	auto firstMessages  = first ->getMessages();
	auto secondMessages = second->getMessages();

	//Compute all verifier checks.
	for (int i = 0; i < len; i++) 
		verified = verified && verifiers[i]->verify(verifiersInput[i], firstMessages[i], secondMessages[i]);

	// return true if all verifiers returned true; false, otherwise.
	return verified;
}

void SigmaANDVerifierComputation::checkInput(shared_ptr<SigmaCommonInput> in) {
	SigmaANDCommonInput* input = (SigmaANDCommonInput*)in.get();
	int inputLen = input->getInputs().size();

	// if number of inputs is not equal to number of verifiers, throw exception.
	if (inputLen != len) {
		throw invalid_argument("number of inputs is different from number of underlying verifiers.");
	}
}